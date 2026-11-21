package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/proccapture"
	"github.com/marmutapp/superbased-observer/internal/procmodel"
)

// Process capture budget persistence (agent migration 212,
// docs/plans/process-capture-budget-plan-2026-11-04.md §9.2,
// docs/process-observability.md §11 "Capture budget").
//
// This file is the ONE writer of process_rollups and process_capture_stats.
// process_runs stays owned by processobs.go: the capture path writes its rows
// through persistRunsTx / addFoldCountsTx, called here inside the same
// transaction as the rollup and stats increments, so a flush lands whole or
// not at all and nothing is counted twice when the observer retries it.
//
// PRIVACY INVARIANT: both tables are NODE-LOCAL, pinned out of orgpush.go by
// tests/invariant/privacy_test.go like process_runs.

// ProcessRollupRow is the read model of one process_rollups row, or of a
// group summed across buckets (ProcessRollupsForSession). JSON tags are the
// summary endpoint's rollup shape (plan §9.3).
type ProcessRollupRow struct {
	ID                 int64     `json:"id,omitempty"`
	SessionID          string    `json:"session_id,omitempty"`
	BucketStart        time.Time `json:"bucket_start,omitzero"`
	GroupKind          string    `json:"group_kind"`
	ParentProcessKey   string    `json:"parent_process_key,omitempty"`
	ActionID           *int64    `json:"action_id,omitempty"`
	ServiceRootKey     string    `json:"service_root_key,omitempty"`
	ExeBasename        string    `json:"exe_basename"`
	ArgvTemplateHash   string    `json:"argv_template_hash,omitempty"`
	ExampleArgvPreview string    `json:"example_argv_preview,omitempty"`
	ExampleProcessKey  string    `json:"example_process_key,omitempty"`
	Count              int64     `json:"count"`
	FailedCount        int64     `json:"failed_count"`
	DurationSumMs      int64     `json:"duration_sum_ms"`
	DurationMaxMs      int64     `json:"duration_max_ms"`
	CPUSumMs           int64     `json:"cpu_sum_ms"`
	PeakRSSBytes       int64     `json:"peak_rss_bytes"`
	FirstSeen          time.Time `json:"first_seen,omitzero"`
	LastSeen           time.Time `json:"last_seen,omitzero"`
}

// bucketStamp formats a rollup bucket start (bucket-aligned, whole seconds).
func bucketStamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// PersistCapture implements processobs.CaptureSink: the exemplar runs, the
// fold increments, the rollup increments and the stats increments of one
// observer flush, in ONE transaction. Returns the number of runs written.
func (s *Store) PersistCapture(ctx context.Context, runs []procmodel.ProcessRun, delta proccapture.Delta) (int, error) {
	if len(runs) == 0 && delta.Empty() {
		return 0, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store.PersistCapture: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := persistRunsTx(ctx, tx, runs); err != nil {
		return 0, fmt.Errorf("store.PersistCapture: runs: %w", err)
	}
	if err := addFoldCountsTx(ctx, tx, delta.Folds); err != nil {
		return 0, fmt.Errorf("store.PersistCapture: %w", err)
	}
	if err := upsertRollupsTx(ctx, tx, delta.Rollups); err != nil {
		return 0, fmt.Errorf("store.PersistCapture: %w", err)
	}
	if err := upsertCaptureStatsTx(ctx, tx, delta.Stats, time.Now()); err != nil {
		return 0, fmt.Errorf("store.PersistCapture: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store.PersistCapture: commit: %w", err)
	}
	return len(runs), nil
}

// upsertRollupsTx adds each increment to its group row, NULL-safe on
// session_id (the machine rollup): UPDATE first, INSERT when no row matched.
// A plain ON CONFLICT cannot merge the machine rollup, because SQLite's UNIQUE
// index treats NULL session ids as distinct.
func upsertRollupsTx(ctx context.Context, tx *sql.Tx, rollups []proccapture.Rollup) error {
	if len(rollups) == 0 {
		return nil
	}
	upd, err := tx.PrepareContext(ctx, `
		UPDATE process_rollups SET
		    count           = count + ?,
		    failed_count    = failed_count + ?,
		    duration_sum_ms = duration_sum_ms + ?,
		    duration_max_ms = MAX(duration_max_ms, ?),
		    cpu_sum_ms      = cpu_sum_ms + ?,
		    peak_rss_bytes  = MAX(peak_rss_bytes, ?),
		    first_seen      = CASE WHEN first_seen IS NULL OR (? IS NOT NULL AND ? < first_seen) THEN ? ELSE first_seen END,
		    last_seen       = CASE WHEN last_seen IS NULL OR (? IS NOT NULL AND ? > last_seen) THEN ? ELSE last_seen END,
		    action_id            = COALESCE(action_id, ?),
		    example_argv_preview = COALESCE(example_argv_preview, ?),
		    example_process_key  = COALESCE(example_process_key, ?)
		 WHERE session_id IS ? AND bucket_start = ? AND group_kind = ? AND parent_process_key = ?
		   AND service_root_key = ? AND exe_basename = ? AND argv_template_hash = ?`)
	if err != nil {
		return fmt.Errorf("upsertRollups: prepare update: %w", err)
	}
	defer upd.Close()
	ins, err := tx.PrepareContext(ctx, `
		INSERT INTO process_rollups (
		    session_id, bucket_start, group_kind, parent_process_key, action_id,
		    service_root_key, exe_basename, argv_template_hash,
		    example_argv_preview, example_process_key,
		    count, failed_count, duration_sum_ms, duration_max_ms, cpu_sum_ms, peak_rss_bytes,
		    first_seen, last_seen
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("upsertRollups: prepare insert: %w", err)
	}
	defer ins.Close()
	for i, r := range rollups {
		k := r.Key
		first, last := nullableTimestamp(r.FirstSeen), nullableTimestamp(r.LastSeen)
		res, err := upd.ExecContext(ctx,
			r.Count, r.FailedCount, r.DurationSumMs, r.DurationMaxMs, r.CPUSumMs, r.PeakRSSBytes,
			first, first, first, last, last, last,
			nullableInt64(r.ActionID), nullableString(r.ExampleArgvPreview), nullableString(r.ExampleProcessKey),
			nullableString(k.SessionID), bucketStamp(k.BucketStart), string(k.Kind), k.ParentProcessKey,
			k.ServiceRootKey, k.ExeBasename, k.ArgvTemplateHash)
		if err != nil {
			return fmt.Errorf("upsertRollups: update[%d]: %w", i, err)
		}
		if n, _ := res.RowsAffected(); n > 0 {
			continue
		}
		if _, err := ins.ExecContext(ctx,
			nullableString(k.SessionID), bucketStamp(k.BucketStart), string(k.Kind), k.ParentProcessKey,
			nullableInt64(r.ActionID), k.ServiceRootKey, k.ExeBasename, k.ArgvTemplateHash,
			nullableString(r.ExampleArgvPreview), nullableString(r.ExampleProcessKey),
			r.Count, r.FailedCount, r.DurationSumMs, r.DurationMaxMs, r.CPUSumMs, r.PeakRSSBytes,
			first, last); err != nil {
			return fmt.Errorf("upsertRollups: insert[%d]: %w", i, err)
		}
	}
	return nil
}

// upsertCaptureStatsTx adds each session's increments to its stats row (the empty
// session id is the machine).
func upsertCaptureStatsTx(ctx context.Context, tx *sql.Tx, stats map[string]proccapture.Stats, now time.Time) error {
	if len(stats) == 0 {
		return nil
	}
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO process_capture_stats (
		    session_id, observed, kept, folded, rolled_up, service_kept, service_rolled_up,
		    dropped, budget_hits, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(session_id) DO UPDATE SET
		    observed          = observed + excluded.observed,
		    kept              = kept + excluded.kept,
		    folded            = folded + excluded.folded,
		    rolled_up         = rolled_up + excluded.rolled_up,
		    service_kept      = service_kept + excluded.service_kept,
		    service_rolled_up = service_rolled_up + excluded.service_rolled_up,
		    dropped           = dropped + excluded.dropped,
		    budget_hits       = budget_hits + excluded.budget_hits,
		    updated_at        = excluded.updated_at`)
	if err != nil {
		return fmt.Errorf("upsertCaptureStats: prepare: %w", err)
	}
	defer stmt.Close()
	ts := timestamp(now)
	for sess, st := range stats {
		if _, err := stmt.ExecContext(ctx, sess, st.Observed, st.Kept, st.Folded, st.RolledUp,
			st.ServiceKept, st.ServiceRolledUp, st.Dropped, st.BudgetHits, ts); err != nil {
			return fmt.Errorf("upsertCaptureStats %q: %w", sess, err)
		}
	}
	return nil
}

// ProcessCaptureStatsForSession returns a session's capture counters ("" for
// the machine). ok=false means the session has no stats row: its process rows
// predate the capture budget (the summary's `legacy` flag).
func (s *Store) ProcessCaptureStatsForSession(ctx context.Context, sessionID string) (proccapture.Stats, bool, error) {
	var st proccapture.Stats
	err := s.db.QueryRowContext(ctx, `
		SELECT observed, kept, folded, rolled_up, service_kept, service_rolled_up, dropped, budget_hits
		  FROM process_capture_stats WHERE session_id = ?`, sessionID).
		Scan(&st.Observed, &st.Kept, &st.Folded, &st.RolledUp, &st.ServiceKept, &st.ServiceRolledUp, &st.Dropped, &st.BudgetHits)
	if err == sql.ErrNoRows {
		return proccapture.Stats{}, false, nil
	}
	if err != nil {
		return proccapture.Stats{}, false, fmt.Errorf("store.ProcessCaptureStatsForSession: %w", err)
	}
	return st, true, nil
}

// ProcessRollupsForSession returns a session's rollup groups SUMMED ACROSS
// BUCKETS (one row per group kind, parent, service root, executable and argv
// template), top limit by count, the shape the summary endpoint shows.
// sessionID "" reads the machine rollup. limit <= 0 means 200.
func (s *Store) ProcessRollupsForSession(ctx context.Context, sessionID string, limit int) ([]ProcessRollupRow, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT COALESCE(session_id, ''), group_kind, parent_process_key, MIN(action_id), service_root_key,
		       exe_basename, argv_template_hash, MIN(example_argv_preview), MIN(example_process_key),
		       SUM(count), SUM(failed_count), SUM(duration_sum_ms), MAX(duration_max_ms),
		       SUM(cpu_sum_ms), MAX(peak_rss_bytes), MIN(first_seen), MAX(last_seen)
		  FROM process_rollups
		 WHERE session_id IS ?
		 GROUP BY group_kind, parent_process_key, service_root_key, exe_basename, argv_template_hash
		 ORDER BY SUM(count) DESC, exe_basename ASC
		 LIMIT ?`, nullableString(sessionID), limit)
	if err != nil {
		return nil, fmt.Errorf("store.ProcessRollupsForSession: %w", err)
	}
	defer rows.Close()
	var out []ProcessRollupRow
	for rows.Next() {
		var r ProcessRollupRow
		var actionID sql.NullInt64
		var argv, key, first, last sql.NullString
		if err := rows.Scan(&r.SessionID, &r.GroupKind, &r.ParentProcessKey, &actionID, &r.ServiceRootKey,
			&r.ExeBasename, &r.ArgvTemplateHash, &argv, &key,
			&r.Count, &r.FailedCount, &r.DurationSumMs, &r.DurationMaxMs,
			&r.CPUSumMs, &r.PeakRSSBytes, &first, &last); err != nil {
			return nil, fmt.Errorf("store.ProcessRollupsForSession: scan: %w", err)
		}
		fillRollupNullables(&r, actionID, argv, key, first, last)
		out = append(out, r)
	}
	return out, rows.Err()
}

// ProcessRollupBucketsForSession returns a session's rollup rows bucket by
// bucket whose bucket starts in [from, to) (a zero bound is open), oldest
// first, at most limit (<= 0 means 2000): the timeline / windowed read.
func (s *Store) ProcessRollupBucketsForSession(ctx context.Context, sessionID string, from, to time.Time, limit int) ([]ProcessRollupRow, error) {
	if limit <= 0 {
		limit = 2000
	}
	lo, hi := "", "9999"
	if !from.IsZero() {
		lo = bucketStamp(from)
	}
	if !to.IsZero() {
		hi = bucketStamp(to)
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, COALESCE(session_id, ''), bucket_start, group_kind, parent_process_key, action_id,
		       service_root_key, exe_basename, argv_template_hash, example_argv_preview, example_process_key,
		       count, failed_count, duration_sum_ms, duration_max_ms, cpu_sum_ms, peak_rss_bytes,
		       first_seen, last_seen
		  FROM process_rollups
		 WHERE session_id IS ? AND bucket_start >= ? AND bucket_start < ?
		 ORDER BY bucket_start ASC, id ASC
		 LIMIT ?`, nullableString(sessionID), lo, hi, limit)
	if err != nil {
		return nil, fmt.Errorf("store.ProcessRollupBucketsForSession: %w", err)
	}
	defer rows.Close()
	var out []ProcessRollupRow
	for rows.Next() {
		var r ProcessRollupRow
		var bucket string
		var actionID sql.NullInt64
		var argv, key, first, last sql.NullString
		if err := rows.Scan(&r.ID, &r.SessionID, &bucket, &r.GroupKind, &r.ParentProcessKey, &actionID,
			&r.ServiceRootKey, &r.ExeBasename, &r.ArgvTemplateHash, &argv, &key,
			&r.Count, &r.FailedCount, &r.DurationSumMs, &r.DurationMaxMs, &r.CPUSumMs, &r.PeakRSSBytes,
			&first, &last); err != nil {
			return nil, fmt.Errorf("store.ProcessRollupBucketsForSession: scan: %w", err)
		}
		r.BucketStart = parseStamp(bucket)
		fillRollupNullables(&r, actionID, argv, key, first, last)
		out = append(out, r)
	}
	return out, rows.Err()
}

func fillRollupNullables(r *ProcessRollupRow, actionID sql.NullInt64, argv, key, first, last sql.NullString) {
	if actionID.Valid {
		v := actionID.Int64
		r.ActionID = &v
	}
	r.ExampleArgvPreview = argv.String
	r.ExampleProcessKey = key.String
	if first.Valid {
		r.FirstSeen = parseStamp(first.String)
	}
	if last.Valid {
		r.LastSeen = parseStamp(last.String)
	}
}

// Capture-history bounds for LoadCaptureHistory (plan §9.3: up to the last 7
// days, at most 200,000 rows).
const (
	CaptureHistoryDays    = 7
	CaptureHistoryMaxRows = 200000
)

// LoadCaptureHistory loads the node's most recent stored process runs as
// proccapture.RunFacts for proccapture.Estimate / proccapture.Replay: runs
// started since `since` (zero = CaptureHistoryDays ago), newest limit rows
// (<= 0 or above the cap = CaptureHistoryMaxRows), returned oldest first.
// StoredBytes / MetricBytes carry the measured lengths of the variable
// columns; SideEffects marks a run with any process_events row; findings are
// derived with procmodel.DeriveFindings, the same table the read path uses.
// A stored row without a session was held for correlation by definition.
func (s *Store) LoadCaptureHistory(ctx context.Context, since time.Time, limit int) ([]proccapture.RunFacts, error) {
	if since.IsZero() {
		since = time.Now().Add(-CaptureHistoryDays * 24 * time.Hour)
	}
	if limit <= 0 || limit > CaptureHistoryMaxRows {
		limit = CaptureHistoryMaxRows
	}
	stored, err := s.loadCaptureRows(ctx, "LoadCaptureHistory",
		`pr.started_at >= ? ORDER BY pr.started_at DESC LIMIT ?`, timestamp(since), limit)
	if err != nil {
		return nil, err
	}
	out := make([]proccapture.RunFacts, len(stored))
	for i := range stored {
		// Newest first from the query; returned oldest first.
		out[len(stored)-1-i] = stored[i].Facts
	}
	return out, nil
}

// LoadSessionCaptureRows loads every stored process run of one session as
// proccapture.StoredRun (row id, stored capture_class, facts), oldest first:
// the input of proccapture.PlanCompaction for `observer process compact` and
// of the would-keep replay in `observer process stats`. The facts are filled
// exactly as LoadCaptureHistory fills them.
func (s *Store) LoadSessionCaptureRows(ctx context.Context, sessionID string) ([]proccapture.StoredRun, error) {
	if sessionID == "" {
		return nil, nil
	}
	return s.loadCaptureRows(ctx, "LoadSessionCaptureRows",
		`pr.session_id = ? ORDER BY pr.started_at ASC, pr.id ASC`, sessionID)
}

// loadCaptureRows is the one query behind LoadCaptureHistory and
// LoadSessionCaptureRows; tail is the WHERE / ORDER BY / LIMIT clause over
// the pr alias. A run has side effects when any process_events row names it
// by key or by row id; the key set is one uncorrelated subquery SQLite
// evaluates once (process_events has no process_key index, so a correlated
// EXISTS per run would scan the table per row).
func (s *Store) loadCaptureRows(ctx context.Context, who, tail string, args ...any) ([]proccapture.StoredRun, error) {
	//nolint:gosec // tail is one of this file's literal clauses.
	rows, err := s.db.QueryContext(ctx, `
		SELECT pr.id, COALESCE(pr.capture_class, ''),
		       pr.process_key, COALESCE(pr.parent_process_key, ''), COALESCE(pr.exe_basename, ''),
		       COALESCE(pr.exe_path, ''), COALESCE(pp.exe_basename, ''),
		       COALESCE(pr.argv_preview, ''), COALESCE(pr.cwd, ''), COALESCE(pr.session_id, ''),
		       COALESCE(pr.attribution_source, ''), COALESCE(pr.action_id, 0),
		       pr.started_at, pr.last_seen_at, pr.exited_at, pr.exit_code, pr.exit_signal,
		       COALESCE(pr.duration_ms, 0), COALESCE(pr.cpu_user_ms, 0) + COALESCE(pr.cpu_system_ms, 0),
		       COALESCE(pr.max_rss_bytes, 0), COALESCE(pr.uid, 0), COALESCE(pr.euid, 0),
		       COALESCE(pr.service_root_key, ''),
		       COALESCE(length(pr.exe_path), 0) + COALESCE(length(pr.cwd), 0) + COALESCE(length(pr.argv_preview), 0)
		         + COALESCE(length(pr.metric_samples_json), 0),
		       COALESCE(length(pr.metric_samples_json), 0),
		       (pr.process_key IN (SELECT process_key FROM process_events WHERE process_key IS NOT NULL)
		         OR EXISTS (SELECT 1 FROM process_events pe WHERE pe.process_run_id = pr.id))
		  FROM process_runs pr
		  LEFT JOIN process_runs pp ON pp.process_key = pr.parent_process_key
		 WHERE `+tail, args...)
	if err != nil {
		return nil, fmt.Errorf("store.%s: %w", who, err)
	}
	defer rows.Close()
	var out []proccapture.StoredRun
	for rows.Next() {
		var sr proccapture.StoredRun
		f := &sr.Facts
		var class, exePath, startedAt, lastSeen string
		var exitedAt sql.NullString
		var exitCode, exitSignal sql.NullInt64
		var uid, euid int
		var sideEffects int
		if err := rows.Scan(&sr.ID, &class,
			&f.ProcessKey, &f.ParentKey, &f.ExeBasename, &exePath, &f.ParentExeBasename,
			&f.Argv, &f.CWD, &f.SessionID, &f.AttributionSource, &f.ActionID,
			&startedAt, &lastSeen, &exitedAt, &exitCode, &exitSignal,
			&f.DurationMs, &f.CPUMs, &f.PeakRSSBytes, &uid, &euid,
			&f.ServiceRootKey, &f.StoredBytes, &f.MetricBytes, &sideEffects); err != nil {
			return nil, fmt.Errorf("store.%s: scan: %w", who, err)
		}
		sr.Class = proccapture.CaptureClass(class)
		f.Time = parseStamp(startedAt)
		f.Ended = exitedAt.Valid && exitedAt.String != ""
		// A stored exit status counts as a failure even when exited_at is
		// missing: the compaction guard must never read a failure as a success.
		f.Failed = (exitCode.Valid && exitCode.Int64 != 0) || (exitSignal.Valid && exitSignal.Int64 != 0)
		if f.Ended {
			f.AliveFor = time.Duration(f.DurationMs) * time.Millisecond
		} else if ls := parseStamp(lastSeen); ls.After(f.Time) {
			f.AliveFor = ls.Sub(f.Time)
		}
		f.HeldForCorrelation = f.SessionID == ""
		f.SideEffects = sideEffects != 0
		f.FindingsFired = len(procmodel.DeriveFindings([]procmodel.RunFacts{{
			ProcessKey: f.ProcessKey, SessionID: f.SessionID, Attributed: f.SessionID != "",
			ExePath: exePath, ExeBasename: f.ExeBasename, UID: uid, EUID: euid,
		}}))
		out = append(out, sr)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.%s: rows: %w", who, err)
	}
	return out, nil
}

// UnattributedPolicyBatch is the default cap on rows one retention pass
// processes under the unattributed policy (the archival invariant: one capped
// batch per pass, never loop until done).
const UnattributedPolicyBatch = 5000

// UnattributedPolicyResult reports one pass of ApplyUnattributedPolicy.
type UnattributedPolicyResult struct {
	// RowsProcessed is the number of process_runs rows deleted.
	RowsProcessed int
	// RollupGroups is the number of machine-rollup increments written (0 in
	// drop mode).
	RollupGroups int
}

// ApplyUnattributedPolicy runs the unattributed policy (plan §8 ruling 3) for
// ONE capped batch: process_runs rows with no session that started more than
// cfg.PendingHours before now are rolled into the machine rollup
// (session_id NULL, group_kind unattributed) and deleted, or deleted without
// a rollup when cfg.UnattributedMode is "drop". Their process_events and
// network bodies go with them. The machine stats row (empty session id) records the move:
// kept falls (never below zero), rolled_up or dropped rises, and observed is
// raised to cover rows that predate the budget. Copy and delete share one
// transaction. cfg.PendingHours <= 0 or a disabled budget is a no-op; batch
// <= 0 uses UnattributedPolicyBatch.
func (s *Store) ApplyUnattributedPolicy(ctx context.Context, cfg proccapture.Config, now time.Time, batch int) (UnattributedPolicyResult, error) {
	var res UnattributedPolicyResult
	if !cfg.Enabled || cfg.PendingHours <= 0 {
		return res, nil
	}
	if batch <= 0 {
		batch = UnattributedPolicyBatch
	}
	cutoff := timestamp(now.Add(-time.Duration(cfg.PendingHours) * time.Hour))

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return res, fmt.Errorf("store.ApplyUnattributedPolicy: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, `
		SELECT id, process_key, COALESCE(exe_basename, ''), COALESCE(argv_preview, ''), started_at,
		       exited_at, exit_code, exit_signal, COALESCE(duration_ms, 0),
		       COALESCE(cpu_user_ms, 0) + COALESCE(cpu_system_ms, 0), COALESCE(max_rss_bytes, 0)
		  FROM process_runs
		 WHERE session_id IS NULL AND started_at < ?
		 ORDER BY started_at ASC
		 LIMIT ?`, cutoff, batch)
	if err != nil {
		return res, fmt.Errorf("store.ApplyUnattributedPolicy: select: %w", err)
	}
	var ids []int64
	var facts []proccapture.RunFacts
	for rows.Next() {
		var id int64
		var f proccapture.RunFacts
		var startedAt string
		var exitedAt sql.NullString
		var exitCode, exitSignal sql.NullInt64
		if err := rows.Scan(&id, &f.ProcessKey, &f.ExeBasename, &f.Argv, &startedAt,
			&exitedAt, &exitCode, &exitSignal, &f.DurationMs, &f.CPUMs, &f.PeakRSSBytes); err != nil {
			_ = rows.Close()
			return res, fmt.Errorf("store.ApplyUnattributedPolicy: scan: %w", err)
		}
		f.Time = parseStamp(startedAt)
		f.Failed = exitedAt.Valid && ((exitCode.Valid && exitCode.Int64 != 0) || (exitSignal.Valid && exitSignal.Int64 != 0))
		ids = append(ids, id)
		facts = append(facts, f)
	}
	if err := rows.Close(); err != nil {
		return res, fmt.Errorf("store.ApplyUnattributedPolicy: rows: %w", err)
	}
	if len(ids) == 0 {
		return res, nil
	}

	counter := "rolled_up"
	if cfg.UnattributedMode == proccapture.UnattributedDrop {
		counter = "dropped"
	} else {
		rollups := proccapture.RollupUnattributed(facts, cfg)
		if err := upsertRollupsTx(ctx, tx, rollups); err != nil {
			return res, fmt.Errorf("store.ApplyUnattributedPolicy: %w", err)
		}
		res.RollupGroups = len(rollups)
	}

	for _, q := range []string{
		`DELETE FROM process_network_bodies WHERE process_event_id IN (
		     SELECT id FROM process_events WHERE process_run_id = ? OR process_key = (SELECT process_key FROM process_runs WHERE id = ?))`,
		`DELETE FROM process_events WHERE process_run_id = ? OR process_key = (SELECT process_key FROM process_runs WHERE id = ?)`,
	} {
		stmt, err := tx.PrepareContext(ctx, q)
		if err != nil {
			return res, fmt.Errorf("store.ApplyUnattributedPolicy: prepare: %w", err)
		}
		for _, id := range ids {
			if _, err := stmt.ExecContext(ctx, id, id); err != nil {
				_ = stmt.Close()
				return res, fmt.Errorf("store.ApplyUnattributedPolicy: events: %w", err)
			}
		}
		_ = stmt.Close()
	}
	del, err := tx.PrepareContext(ctx, `DELETE FROM process_runs WHERE id = ?`)
	if err != nil {
		return res, fmt.Errorf("store.ApplyUnattributedPolicy: prepare delete: %w", err)
	}
	for _, id := range ids {
		if _, err := del.ExecContext(ctx, id); err != nil {
			_ = del.Close()
			return res, fmt.Errorf("store.ApplyUnattributedPolicy: delete: %w", err)
		}
	}
	_ = del.Close()

	n := int64(len(ids))
	ts := timestamp(now)
	//nolint:gosec // counter is one of two package literals.
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO process_capture_stats (session_id, `+counter+`, observed, updated_at) VALUES ('', ?, ?, ?)
		ON CONFLICT(session_id) DO UPDATE SET
		    kept = MAX(kept - excluded.`+counter+`, 0),
		    `+counter+` = `+counter+` + excluded.`+counter+`,
		    updated_at = excluded.updated_at`, n, n, ts); err != nil {
		return res, fmt.Errorf("store.ApplyUnattributedPolicy: stats: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE process_capture_stats
		   SET observed = MAX(observed, kept + folded + rolled_up + service_kept + service_rolled_up + dropped)
		 WHERE session_id = ''`); err != nil {
		return res, fmt.Errorf("store.ApplyUnattributedPolicy: observed: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return res, fmt.Errorf("store.ApplyUnattributedPolicy: commit: %w", err)
	}
	res.RowsProcessed = len(ids)
	return res, nil
}

// PruneProcessCaptureRows removes process_rollups rows whose bucket started
// more than retentionDays ago and process_capture_stats rows not updated in
// that long ([observer.process].retention_days, the same horizon as the
// runs). retentionDays <= 0 is a no-op. Returns the rows removed.
func (s *Store) PruneProcessCaptureRows(ctx context.Context, retentionDays int) (int, error) {
	if retentionDays <= 0 {
		return 0, nil
	}
	cut := time.Now().UTC().Add(-time.Duration(retentionDays) * 24 * time.Hour)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store.PruneProcessCaptureRows: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var removed int
	r, err := tx.ExecContext(ctx, `DELETE FROM process_rollups WHERE bucket_start < ?`, bucketStamp(cut))
	if err != nil {
		return 0, fmt.Errorf("store.PruneProcessCaptureRows: rollups: %w", err)
	}
	n, _ := r.RowsAffected()
	removed += int(n)
	r, err = tx.ExecContext(ctx, `DELETE FROM process_capture_stats WHERE updated_at < ?`, timestamp(cut))
	if err != nil {
		return 0, fmt.Errorf("store.PruneProcessCaptureRows: stats: %w", err)
	}
	n, _ = r.RowsAffected()
	removed += int(n)
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store.PruneProcessCaptureRows: commit: %w", err)
	}
	return removed, nil
}

// ErrProcessCompactionStale is returned by CompactProcessSession when the
// session's process rows changed between planning and the write (a run was
// added, deleted or rewritten): the plan is discarded, nothing is written,
// and the caller re-plans or skips the session.
var ErrProcessCompactionStale = errors.New("store: session process rows changed since the compaction was planned")

// ProcessCompactionMark is the watermark a compaction plan was computed
// against: the row count, highest row id and latest stored last_seen_at of
// the session's own rows, outside any service subtree
// (ProcessSessionActivity.CompactionMark).
type ProcessCompactionMark struct {
	Rows     int64
	MaxID    int64
	LastSeen string
}

// ProcessCompactionResult reports one applied compaction.
type ProcessCompactionResult struct {
	// Deleted is the number of process_runs rows removed.
	Deleted int64
	// RollupGroups is the number of rollup increments written.
	RollupGroups int
	// Updated is the number of kept legacy rows stamped with a class.
	Updated int
}

// CompactProcessSession applies one session's compaction plan
// (proccapture.PlanCompaction, `observer process compact`) COPY-THEN-DELETE
// in ONE transaction: the rollup increments, the stats increment, the fold
// counts and the class stamps are written first, then the planned rows are
// deleted, so a crash leaves either the old rows or their rollups, never
// neither. The watermark is re-checked inside the transaction (the archival
// rule: a concurrent writer cancels the move); a mismatch returns
// ErrProcessCompactionStale and writes nothing. A service row sighted or added
// meanwhile does not cancel it: the plan never changes a classified row. An
// empty plan is a no-op.
func (s *Store) CompactProcessSession(ctx context.Context, plan proccapture.CompactionPlan, mark ProcessCompactionMark) (ProcessCompactionResult, error) {
	var res ProcessCompactionResult
	if plan.SessionID == "" || plan.Empty() {
		return res, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return res, fmt.Errorf("store.CompactProcessSession: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var now ProcessCompactionMark
	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*), COALESCE(MAX(id), 0), COALESCE(MAX(last_seen_at), '')
		  FROM process_runs WHERE session_id = ? AND `+processOwnRow, plan.SessionID).
		Scan(&now.Rows, &now.MaxID, &now.LastSeen); err != nil {
		return res, fmt.Errorf("store.CompactProcessSession: watermark: %w", err)
	}
	if now != mark {
		return res, ErrProcessCompactionStale
	}
	if err := upsertRollupsTx(ctx, tx, plan.Rollups); err != nil {
		return res, fmt.Errorf("store.CompactProcessSession: %w", err)
	}
	if plan.StatsDelta != (proccapture.Stats{}) || !plan.HadStats {
		if err := upsertCaptureStatsTx(ctx, tx, map[string]proccapture.Stats{plan.SessionID: plan.StatsDelta}, time.Now()); err != nil {
			return res, fmt.Errorf("store.CompactProcessSession: %w", err)
		}
	}
	if err := addFoldCountsTx(ctx, tx, plan.Folds); err != nil {
		return res, fmt.Errorf("store.CompactProcessSession: %w", err)
	}
	if err := setCaptureClassTx(ctx, tx, plan.Updates); err != nil {
		return res, fmt.Errorf("store.CompactProcessSession: %w", err)
	}
	n, err := deleteRunsByIDTx(ctx, tx, plan.Delete)
	if err != nil {
		return res, fmt.Errorf("store.CompactProcessSession: %w", err)
	}
	if n != int64(len(plan.Delete)) {
		return res, fmt.Errorf("store.CompactProcessSession: deleted %d of %d planned rows", n, len(plan.Delete))
	}
	if err := tx.Commit(); err != nil {
		return res, fmt.Errorf("store.CompactProcessSession: commit: %w", err)
	}
	res.Deleted = n
	res.RollupGroups = len(plan.Rollups)
	res.Updated = len(plan.Updates)
	return res, nil
}

// ProcessRollupRowCount returns how many process_rollups rows (buckets) a
// session holds ("" for the machine rollup), for `observer process stats`.
func (s *Store) ProcessRollupRowCount(ctx context.Context, sessionID string) (int64, error) {
	var n int64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM process_rollups WHERE session_id IS ?`,
		nullableString(sessionID)).Scan(&n); err != nil {
		return 0, fmt.Errorf("store.ProcessRollupRowCount: %w", err)
	}
	return n, nil
}
