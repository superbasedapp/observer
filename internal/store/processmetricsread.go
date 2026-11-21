package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/procmodel"
)

// The session resource-metrics READ seam (GET /api/session/<id>/metrics).
//
// The metrics series needs one thing per process row: its sample ring, plus
// the process key, start and exit flag. It never needs argv, env posture,
// paths, namespaces or attribution, so this seam selects only
// processMetricRunCols and skips rows with no ring at all (a NULL
// metric_samples_json is an empty ring: marshalMetricSamples never writes
// "[]").
//
// It is also INCREMENTAL. A long session holds ~100k rows whose rings almost
// all belong to processes that exited long ago and will never be rewritten.
// The caller keeps the facts of those SETTLED rows (last_seen_at before a
// cutoff) and hands back the ProcessMetricsSettled mark it got; while the
// session's settled rows still match that mark, only the unsettled tail is
// read and decoded. A mismatch (a row attached late by correlation, deleted
// by compaction, or rewritten so it moved past the cutoff) falls back to a
// full read, so a stale mark costs a re-read, never a wrong answer.
//
// PRIVACY INVARIANT: node-local tables only; nothing here is on the org wire.

// processMetricRunCols is the column set a metrics read decodes, in scan
// order. Pinned by TestProcessMetricRunColsAreMetricOnly: argv / env / path
// columns must never appear here.
const processMetricRunCols = `id, process_key, started_at,
	COALESCE(exited_at, '') != '',
	COALESCE(last_seen_at < ?, 0),
	metric_samples_json`

// ProcessMetricRun is one ring-bearing process row reduced to what the
// session metrics series needs.
type ProcessMetricRun struct {
	ID         int64
	ProcessKey string
	StartedAt  time.Time
	Exited     bool
	// Settled reports last_seen_at < the result's Settled.Before: the row is
	// counted in that mark, so the caller folds it into its settled facts.
	Settled bool
	Samples []procmodel.MetricSample
}

// ProcessMetricsSettled marks the settled part of a session's ring-bearing
// rows: those last seen before Before (a whole-second stamp prefix, see
// secondFloor; "" settles nothing), with their count and id sum. It is
// opaque to the caller, which only stores it and passes it back.
type ProcessMetricsSettled struct {
	Before string
	Rows   int64
	IDSum  int64
}

// ProcessMetricsQuery parameterises ProcessMetricsForSession.
type ProcessMetricsQuery struct {
	// Known is the mark of the caller's cached settled facts, nil for none.
	// When the session's settled rows still match it, only the rows not
	// settled under Known.Before are read.
	Known *ProcessMetricsSettled
	// SettleAge is how long before the session's newest sighting a row must
	// have been last seen to count as settled after this read. <= 0 settles
	// nothing new. The cutoff never moves backwards past Known.Before.
	SettleAge time.Duration
}

// ProcessMetricsResult is one metrics read of a session.
type ProcessMetricsResult struct {
	// Total counts every process row of the session, ring or not.
	Total int64
	// Full is true when Runs holds every ring-bearing row of the session;
	// false when Known matched and Runs is only the unsettled tail.
	Full bool
	// Settled is the mark covering every row settled after this read: the
	// rows Known covered (when it matched) plus the Runs flagged Settled.
	Settled ProcessMetricsSettled
	// Runs is oldest first (started_at, then pid): the same relative order as
	// ProcessRunsForSession, so a series summed over them adds up identically.
	Runs []ProcessMetricRun
}

// ProcessMetricsForSession reads a session's ring-bearing process rows for
// the metrics series, all of them or (Known matching) only the unsettled
// tail. The mark check and the read run in ONE read transaction, so they see
// the same snapshot.
func (s *Store) ProcessMetricsForSession(ctx context.Context, sessionID string, q ProcessMetricsQuery) (ProcessMetricsResult, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return ProcessMetricsResult{}, fmt.Errorf("store.ProcessMetricsForSession: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	known := ProcessMetricsSettled{}
	if q.Known != nil {
		known = *q.Known
	}
	var res ProcessMetricsResult
	var newest string
	var rows, idSum int64
	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*), COALESCE(MAX(last_seen_at), ''),
		       COALESCE(SUM(metric_samples_json IS NOT NULL AND last_seen_at < ?), 0),
		       COALESCE(SUM(CASE WHEN metric_samples_json IS NOT NULL AND last_seen_at < ? THEN id END), 0)
		  FROM process_runs WHERE session_id = ?`,
		known.Before, known.Before, sessionID).Scan(&res.Total, &newest, &rows, &idSum); err != nil {
		return ProcessMetricsResult{}, fmt.Errorf("store.ProcessMetricsForSession: mark: %w", err)
	}
	hit := q.Known != nil && rows == known.Rows && idSum == known.IDSum
	res.Full = !hit

	before := settledBefore(newest, q.SettleAge)
	query := `SELECT ` + processMetricRunCols + ` FROM process_runs
		WHERE session_id = ? AND metric_samples_json IS NOT NULL`
	args := []any{before, sessionID}
	if hit {
		if before < known.Before {
			before = known.Before
			args[0] = before
		}
		res.Settled = known
		query += ` AND NOT COALESCE(last_seen_at < ?, 0)`
		args = append(args, known.Before)
	}
	res.Settled.Before = before
	query += ` ORDER BY started_at ASC, pid ASC`

	//nolint:gosec // query is built from this file's literal fragments.
	rs, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return ProcessMetricsResult{}, fmt.Errorf("store.ProcessMetricsForSession: query: %w", err)
	}
	defer rs.Close()
	for rs.Next() {
		var r ProcessMetricRun
		var started, ring string
		if err := rs.Scan(&r.ID, &r.ProcessKey, &started, &r.Exited, &r.Settled, &ring); err != nil {
			return ProcessMetricsResult{}, fmt.Errorf("store.ProcessMetricsForSession: scan: %w", err)
		}
		r.StartedAt = parseStamp(started)
		r.Samples = parseMetricSamples(ring)
		if r.Settled {
			res.Settled.Rows++
			res.Settled.IDSum += r.ID
		}
		res.Runs = append(res.Runs, r)
	}
	if err := rs.Err(); err != nil {
		return ProcessMetricsResult{}, fmt.Errorf("store.ProcessMetricsForSession: rows: %w", err)
	}
	return res, nil
}

// settledBefore is the settle cutoff for a session whose newest sighting is
// the stored stamp newest: age before it, at whole-second resolution. ""
// (settles nothing) when there is no sighting or no age.
func settledBefore(newest string, age time.Duration) string {
	if age <= 0 {
		return ""
	}
	t := parseStamp(newest)
	if t.IsZero() {
		return ""
	}
	return secondFloor(t.Add(-age))
}
