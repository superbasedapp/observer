package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/archive"
)

// Bucket B (process capture) hot-side archival seam — P3 of
// docs/plans/observer-corpus-archival-lazyload-design-2026-08-26.md §9.
//
// This file owns: the day-window staleness selector, the window shape guard,
// the streaming export, the ONE transaction that deletes a window's hot rows
// and writes its marker, and the process_archived_windows marker table
// (migration 093). The archive file itself is never opened from here —
// internal/archivesvc composes the two sides.
//
// The invariant that governs every line: THIS BUCKET IS NOT REGENERABLE
// (design §2.2). Bucket A can afford a bug because a re-index fixes it. Here
// the archive copy IS the copy, so the delete happens only behind the same
// verification Bucket A's delete happens behind, and every guard errs toward
// "leave the rows hot".

// ErrArchiveWindowChanged aborts a Bucket B move because the window's hot rows
// changed between the copy and the delete. Wraps [archive.ErrProjectChanged]
// so the composer recognises the outcome without importing this package.
var ErrArchiveWindowChanged = fmt.Errorf("store: %w", archive.ErrProjectChanged)

// hotWindowPredicate is the WHERE clause that selects one day's rows per table
// on the HOT side.
//
// It deliberately mirrors PruneProcessRows exactly, including its asymmetry:
// runs are scoped by started_at, events by timestamp, and bodies THROUGH their
// parent event rather than by any clock of their own. Those are two independent
// horizons, so a run and its own events can fall on different sides of a day
// boundary — and reproducing that shape rather than "improving" it is what
// makes the archive move the same set the delete would have removed.
func hotWindowPredicate(table string) (string, bool) {
	switch table {
	case "process_runs":
		return `started_at >= ? AND started_at < ?`, true
	case "process_events":
		return `timestamp >= ? AND timestamp < ?`, true
	case "process_network_bodies":
		return `process_event_id IN (SELECT id FROM process_events WHERE timestamp >= ? AND timestamp < ?)`, true
	}
	return "", false
}

// ProcessStaleWindows lists the UTC days whose process capture is older than
// archiveDays, coldest first, capped at max.
//
// archiveDays ≤ 0 disables the sweep entirely (nil, nil) — the same
// short-circuit shape PruneProcessRows and CodeIntelStaleProjects use, so the
// caller can pass a config value straight through.
//
// TODAY is never eligible: the cutoff is a whole number of days back from now,
// and the query asks for days strictly before it, so a window still receiving
// writes is not offered. That is the first of the two things standing between
// this sweep and a live process trail; the shape guard is the second.
func (s *Store) ProcessStaleWindows(ctx context.Context, archiveDays, maxWindows int) ([]archive.WindowCandidate, error) {
	if archiveDays <= 0 {
		return nil, nil
	}
	if maxWindows <= 0 {
		maxWindows = archive.DefaultMaxUnitsPerPass
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -archiveDays).Format("2006-01-02")
	rows, err := s.db.QueryContext(ctx,
		`SELECT day, SUM(n) AS rows_total FROM (
		     SELECT substr(started_at, 1, 10) AS day, COUNT(*) AS n
		       FROM process_runs WHERE started_at < ? GROUP BY day
		     UNION ALL
		     SELECT substr(timestamp, 1, 10) AS day, COUNT(*) AS n
		       FROM process_events WHERE timestamp < ? GROUP BY day
		 )
		 WHERE day != ''
		 GROUP BY day ORDER BY day LIMIT ?`, cutoff, cutoff, maxWindows)
	if err != nil {
		return nil, fmt.Errorf("store.ProcessStaleWindows: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []archive.WindowCandidate
	for rows.Next() {
		var c archive.WindowCandidate
		if err := rows.Scan(&c.Window.Day, &c.Rows); err != nil {
			return nil, fmt.Errorf("store.ProcessStaleWindows: scan: %w", err)
		}
		if c.Window.Valid() {
			out = append(out, c)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.ProcessStaleWindows: %w", err)
	}
	return out, nil
}

// ProcessWindowShape reports the guard pair the delete re-checks.
//
// MaxLastSeen is the field that makes this correct rather than merely
// plausible. process_runs rows MUTATE: store.PersistRuns upserts on
// process_key, refreshing last_seen_at, the exit columns and the metric
// samples of a process that started days ago and is still alive. A count and a
// MAX(id) would both report "unchanged" while the row's contents moved on, and
// the copy would then be a stale snapshot the delete happily destroys the
// original of. MAX(last_seen_at) moves whenever any run in the window is
// touched.
//
// process_events and process_network_bodies are insert-only, and
// PersistProcessEvents writes a body in the SAME transaction as its event, so
// a new body always arrives with a new event — the event count and MAX(id)
// cover the bodies too. The body count is captured anyway, because it is what
// the marker reports and a free consistency cross-check.
func (s *Store) ProcessWindowShape(ctx context.Context, w archive.Window) (archive.WindowShape, error) {
	var sh archive.WindowShape
	if !w.Valid() {
		return sh, fmt.Errorf("store.ProcessWindowShape: invalid window %q", w.Day)
	}
	lo, hi := w.Bounds()
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(MAX(id), 0), COALESCE(MAX(last_seen_at), '')
		   FROM process_runs WHERE started_at >= ? AND started_at < ?`, lo, hi).
		Scan(&sh.Runs, &sh.MaxRunID, &sh.MaxLastSeen); err != nil {
		return sh, fmt.Errorf("store.ProcessWindowShape: runs: %w", err)
	}
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(MAX(id), 0)
		   FROM process_events WHERE timestamp >= ? AND timestamp < ?`, lo, hi).
		Scan(&sh.Events, &sh.MaxEventID); err != nil {
		return sh, fmt.Errorf("store.ProcessWindowShape: events: %w", err)
	}
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM process_network_bodies
		  WHERE process_event_id IN (SELECT id FROM process_events WHERE timestamp >= ? AND timestamp < ?)`,
		lo, hi).Scan(&sh.Bodies); err != nil {
		return sh, fmt.Errorf("store.ProcessWindowShape: bodies: %w", err)
	}
	return sh, nil
}

// ProcessExportWindow streams one day's process rows into sink, parent-first,
// in bounded batches.
//
// SELECT * is deliberate: the driver's own column list is the single source of
// truth for what gets archived, so a column added by a future migration is
// carried without anyone remembering to update a transcription — and a column
// the archive schema lacks fails LOUDLY at copy time, before any delete. See
// archive.RowBatch for the full rationale.
func (s *Store) ProcessExportWindow(ctx context.Context, w archive.Window, batchRows int, sink archive.WindowSink) error {
	if !w.Valid() {
		return fmt.Errorf("store.ProcessExportWindow: invalid window %q", w.Day)
	}
	lo, hi := w.Bounds()
	for _, table := range archive.ProcessTables {
		pred, ok := hotWindowPredicate(table)
		if !ok {
			return fmt.Errorf("store.ProcessExportWindow: no predicate for %q", table)
		}
		//nolint:gosec // table is from archive.ProcessTables; pred is a package literal.
		q := `SELECT * FROM ` + table + ` WHERE ` + pred + ` ORDER BY id`
		rows, err := s.db.QueryContext(ctx, q, lo, hi)
		if err != nil {
			return fmt.Errorf("store.ProcessExportWindow(%s): %w", table, err)
		}
		err = archive.StreamRows(ctx, rows, table, batchRows, "", sink)
		_ = rows.Close()
		if err != nil {
			return fmt.Errorf("store.ProcessExportWindow(%s): %w", table, err)
		}
	}
	return nil
}

// ProcessWindowDigest fingerprints a window's CURRENT hot rows by streaming the
// SAME exporter the copy uses through a digest sink. A digest built from a
// second set of aggregate queries would verify those queries, not the rows the
// copy read.
func (s *Store) ProcessWindowDigest(ctx context.Context, w archive.Window, batchRows int) (*archive.WindowDigest, error) {
	sink := archive.NewWindowDigestSink()
	if err := s.ProcessExportWindow(ctx, w, batchRows, sink); err != nil {
		return nil, err
	}
	return sink.Digest(), nil
}

// ProcessArchiveComplete finishes one Bucket B move: it re-checks the window's
// shape, deletes the hot rows, and writes the marker — ALL IN ONE TRANSACTION.
//
// Crash states, by construction:
//   - copied, not deleted → next pass re-copies (idempotent upsert) and
//     deletes. No loss.
//   - deleted AND marked → done.
//
// There is deliberately no third state where the rows are gone but the marker
// is missing, which for the only-copy bucket would make vanished capture
// indistinguishable from capture that never happened.
//
// It must be called ONLY after the cold copy has been read back and verified
// ([archive.VerifyWindow]). It verifies nothing itself; it is the last,
// irreversible step and assumes its caller earned the right to take it.
func (s *Store) ProcessArchiveComplete(ctx context.Context, c archive.WindowCompletion) error {
	if !c.Window.Valid() {
		return fmt.Errorf("store.ProcessArchiveComplete: invalid window %q", c.Window.Day)
	}
	lo, hi := c.Window.Bounds()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store.ProcessArchiveComplete: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var now archive.WindowShape
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(MAX(id), 0), COALESCE(MAX(last_seen_at), '')
		   FROM process_runs WHERE started_at >= ? AND started_at < ?`, lo, hi).
		Scan(&now.Runs, &now.MaxRunID, &now.MaxLastSeen); err != nil {
		return fmt.Errorf("store.ProcessArchiveComplete: re-check runs: %w", err)
	}
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(MAX(id), 0)
		   FROM process_events WHERE timestamp >= ? AND timestamp < ?`, lo, hi).
		Scan(&now.Events, &now.MaxEventID); err != nil {
		return fmt.Errorf("store.ProcessArchiveComplete: re-check events: %w", err)
	}
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM process_network_bodies
		  WHERE process_event_id IN (SELECT id FROM process_events WHERE timestamp >= ? AND timestamp < ?)`,
		lo, hi).Scan(&now.Bodies); err != nil {
		return fmt.Errorf("store.ProcessArchiveComplete: re-check bodies: %w", err)
	}
	if !now.Equal(c.ExpectedShape) {
		return fmt.Errorf("%w: %s (%+v -> %+v)", ErrArchiveWindowChanged, c.Window.Day, c.ExpectedShape, now)
	}

	// Children first. The bodies predicate reads process_events, so deleting
	// events before bodies would leave every body in the window unreachable
	// and undeleted — orphan rows in the table that dominates Bucket B's
	// bytes, which is the opposite of the point.
	for i := len(archive.ProcessTables) - 1; i >= 0; i-- {
		table := archive.ProcessTables[i]
		pred, ok := hotWindowPredicate(table)
		if !ok {
			return fmt.Errorf("store.ProcessArchiveComplete: no predicate for %q", table)
		}
		//nolint:gosec // table is from archive.ProcessTables; pred is a package literal.
		if _, err := tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE `+pred, lo, hi); err != nil {
			return fmt.Errorf("store.ProcessArchiveComplete: delete %s: %w", table, err)
		}
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO process_archived_windows (day, archived_at, runs, events, bodies)
		 VALUES (?,?,?,?,?)
		 ON CONFLICT(day) DO UPDATE SET
		   archived_at = excluded.archived_at,
		   runs        = excluded.runs,
		   events      = excluded.events,
		   bodies      = excluded.bodies`,
		c.Window.Day, c.ArchivedAt, c.ExpectedShape.Runs, c.ExpectedShape.Events, c.ExpectedShape.Bodies); err != nil {
		return fmt.Errorf("store.ProcessArchiveComplete: marker: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store.ProcessArchiveComplete: commit: %w", err)
	}
	return nil
}

// ProcessArchivedWindow reports one day's marker, if it has one. A single
// indexed primary-key lookup that never opens the archive file.
func (s *Store) ProcessArchivedWindow(ctx context.Context, day string) (archive.WindowMarker, bool, error) {
	var m archive.WindowMarker
	err := s.db.QueryRowContext(ctx,
		`SELECT day, archived_at, runs, events, bodies FROM process_archived_windows WHERE day = ?`, day).
		Scan(&m.Day, &m.ArchivedAt, &m.Runs, &m.Events, &m.Bodies)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return archive.WindowMarker{}, false, nil
	case err != nil:
		return archive.WindowMarker{}, false, fmt.Errorf("store.ProcessArchivedWindow: %w", err)
	}
	return m, true, nil
}

// ProcessArchivedWindows lists every marker, newest day first, capped.
//
// This is the AGGREGATE surface (design §4.4) — deliberately distinct from any
// scoped read path, and answered entirely from the hot marker table so it never
// joins across the two databases and never enumerates archived ROWS.
func (s *Store) ProcessArchivedWindows(ctx context.Context, limit int) ([]archive.WindowMarker, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT day, archived_at, runs, events, bodies FROM process_archived_windows
		  ORDER BY day DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("store.ProcessArchivedWindows: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []archive.WindowMarker
	for rows.Next() {
		var m archive.WindowMarker
		if err := rows.Scan(&m.Day, &m.ArchivedAt, &m.Runs, &m.Events, &m.Bodies); err != nil {
			return nil, fmt.Errorf("store.ProcessArchivedWindows: scan: %w", err)
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.ProcessArchivedWindows: %w", err)
	}
	return out, nil
}

// AnyProcessWindowArchived reports whether ANY process window has been moved to
// cold storage.
//
// This is the gate the direct-read fallback checks first: one LIMIT-1 lookup
// against a table with one row per archived day. On the overwhelmingly common
// deployment — archival off, or nothing archived yet — a session panel that
// finds no hot rows pays exactly this one query and then answers empty, the
// way it always did. The archive file is opened only when this says there is
// something to look for.
func (s *Store) AnyProcessWindowArchived(ctx context.Context) (bool, error) {
	var one int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM process_archived_windows LIMIT 1`).Scan(&one)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("store.AnyProcessWindowArchived: %w", err)
	}
	return true, nil
}

// DeleteProcessArchivedWindow removes a day's marker. Called by the
// cold-storage expiry sweep AFTER the archived rows themselves are gone: a
// marker that outlived its data would promise recoverable capture that no
// longer exists, which is the dishonest direction.
func (s *Store) DeleteProcessArchivedWindow(ctx context.Context, day string) error {
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM process_archived_windows WHERE day = ?`, day); err != nil {
		return fmt.Errorf("store.DeleteProcessArchivedWindow: %w", err)
	}
	return nil
}
