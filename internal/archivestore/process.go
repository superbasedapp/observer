package archivestore

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/archive"
)

// Bucket B (process capture) cold storage — the write, verify-read, direct-read
// and expiry halves of P3
// (docs/plans/observer-corpus-archival-lazyload-design-2026-08-26.md §2.2, §4.3).
//
// Everything here moves rows as generic column-name/driver-value batches, for
// the reason spelled out on archive.RowBatch: 94 hand-transcribed columns in
// the ONLY-COPY bucket is a silent-misalignment risk this arc cannot take. The
// hot table's own column list is the single source of truth, and this side
// writes by name.

var _ archive.WindowSink = (*Store)(nil)

// archiveTableFor maps a hot process table to its archive mirror. It is the
// ONLY place a table name becomes SQL on this side, so an unknown name is
// rejected rather than interpolated — the batch's Table field arrives from the
// hot exporter, and an allow-list is what keeps that from being an injection
// seam.
func archiveTableFor(hotTable string) (string, error) {
	for _, t := range archive.ProcessTables {
		if t == hotTable {
			return "archive_" + t, nil
		}
	}
	return "", fmt.Errorf("archivestore: %q is not an archivable process table", hotTable)
}

// WriteRows upserts one batch into the matching archive table, keyed on the
// preserved hot row id.
//
// INSERT OR REPLACE is what makes the copy half of copy-then-delete
// re-runnable: a pass that crashes mid-copy and re-runs rewrites the same rows
// onto themselves rather than duplicating them or failing on a conflict.
func (s *Store) WriteRows(ctx context.Context, b archive.RowBatch) error {
	if len(b.Vals) == 0 {
		return nil
	}
	table, err := archiveTableFor(b.Table)
	if err != nil {
		return err
	}
	if len(b.Cols) == 0 {
		return fmt.Errorf("archivestore.WriteRows(%s): batch carried no column names", b.Table)
	}
	cols := make([]string, 0, len(b.Cols)+1)
	for _, c := range b.Cols {
		if err := validIdent(c); err != nil {
			return fmt.Errorf("archivestore.WriteRows(%s): %w", b.Table, err)
		}
		cols = append(cols, c)
	}
	cols = append(cols, "archived_at")
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(cols)), ",")
	//nolint:gosec // table comes from archiveTableFor's allow-list; every column name is validIdent-checked.
	query := `INSERT OR REPLACE INTO ` + table + ` (` + strings.Join(cols, ",") + `) VALUES (` + placeholders + `)`

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("archivestore.WriteRows(%s): begin: %w", b.Table, err)
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("archivestore.WriteRows(%s): prepare: %w", b.Table, err)
	}
	defer func() { _ = stmt.Close() }()
	at := s.now().Unix()
	for _, row := range b.Vals {
		if len(row) != len(b.Cols) {
			return fmt.Errorf("archivestore.WriteRows(%s): row has %d values for %d columns",
				b.Table, len(row), len(b.Cols))
		}
		args := make([]any, 0, len(row)+1)
		args = append(args, row...)
		args = append(args, at)
		if _, err := stmt.ExecContext(ctx, args...); err != nil {
			return fmt.Errorf("archivestore.WriteRows(%s): exec: %w", b.Table, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("archivestore.WriteRows(%s): commit: %w", b.Table, err)
	}
	return nil
}

// validIdent rejects anything that is not a plain SQL identifier. Column names
// reach this package from a driver's rows.Columns() and are therefore already
// trustworthy; the check exists so that stays true if the source ever changes,
// because these names are concatenated into SQL and cannot be parameterized.
func validIdent(s string) error {
	if s == "" || len(s) > 64 {
		return fmt.Errorf("rejected column name %q", s)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9' && i > 0)
		if !ok {
			return fmt.Errorf("rejected column name %q", s)
		}
	}
	return nil
}

// processWindowPredicates maps each archived table to the WHERE clause that
// selects one day's rows on the COLD side.
//
// process_network_bodies has no timestamp of its own — it is a 1:1 extension of
// an event — so it is selected through its parent's window, exactly the way
// store.PruneProcessRows already scopes it hot-side. Keeping the two sides'
// predicate SHAPES identical is what makes "the archive holds what the delete
// would have removed" checkable rather than hopeful.
func coldWindowPredicate(table string) (string, bool) {
	switch table {
	case "process_runs":
		return `started_at >= ? AND started_at < ?`, true
	case "process_events":
		return `timestamp >= ? AND timestamp < ?`, true
	case "process_network_bodies":
		return `process_event_id IN (SELECT id FROM archive_process_events WHERE timestamp >= ? AND timestamp < ?)`, true
	}
	return "", false
}

// StreamProcessWindow reads one archived day back OUT of the archive file and
// pushes it through sink, parent-first.
//
// This is the read half of verification — the mover streams the cold copy
// through a digest sink and compares it against the hot digest. Digesting what
// the writer believed it wrote would verify the writer's memory rather than the
// durable copy, which for the only-copy bucket is the difference between a
// safeguard and a formality.
func (s *Store) StreamProcessWindow(ctx context.Context, w archive.Window, batchRows int, sink archive.WindowSink) error {
	if !w.Valid() {
		return fmt.Errorf("archivestore.StreamProcessWindow: invalid window %q", w.Day)
	}
	if batchRows <= 0 {
		batchRows = archive.DefaultBatchRows
	}
	lo, hi := w.Bounds()
	for _, table := range archive.ProcessTables {
		pred, ok := coldWindowPredicate(table)
		if !ok {
			return fmt.Errorf("archivestore.StreamProcessWindow: no predicate for %q", table)
		}
		//nolint:gosec // table is from archive.ProcessTables; pred is a package literal.
		q := `SELECT * FROM archive_` + table + ` WHERE ` + pred + ` ORDER BY id`
		if err := streamGeneric(ctx, s.db, q, []any{lo, hi}, table, batchRows, "archived_at", sink); err != nil {
			return fmt.Errorf("archivestore.StreamProcessWindow(%s): %w", table, err)
		}
	}
	return nil
}

// ProcessWindowDigest re-reads a window from the archive file and fingerprints
// it — the cold half of [archive.VerifyWindow].
func (s *Store) ProcessWindowDigest(ctx context.Context, w archive.Window, batchRows int) (*archive.WindowDigest, error) {
	sink := archive.NewWindowDigestSink()
	if err := s.StreamProcessWindow(ctx, w, batchRows, sink); err != nil {
		return nil, err
	}
	return sink.Digest(), nil
}

// DeleteProcessWindow removes every archived row for one day, child-to-parent,
// in one transaction.
//
// Two callers, same shape: the mover's PRE-CLEAR of a partial copy left by a
// crashed earlier attempt (the hot rows are still intact at that moment, so it
// is not a "delete first" violation), and the cold-storage expiry sweep.
func (s *Store) DeleteProcessWindow(ctx context.Context, w archive.Window) error {
	if !w.Valid() {
		return fmt.Errorf("archivestore.DeleteProcessWindow: invalid window %q", w.Day)
	}
	lo, hi := w.Bounds()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("archivestore.DeleteProcessWindow: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	// Children first: the bodies predicate reads the events table, so deleting
	// events before bodies would orphan every body in the window.
	for i := len(archive.ProcessTables) - 1; i >= 0; i-- {
		table := archive.ProcessTables[i]
		pred, ok := coldWindowPredicate(table)
		if !ok {
			return fmt.Errorf("archivestore.DeleteProcessWindow: no predicate for %q", table)
		}
		//nolint:gosec // table is from archive.ProcessTables; pred is a package literal.
		if _, err := tx.ExecContext(ctx, `DELETE FROM archive_`+table+` WHERE `+pred, lo, hi); err != nil {
			return fmt.Errorf("archivestore.DeleteProcessWindow(%s): %w", table, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("archivestore.DeleteProcessWindow: commit: %w", err)
	}
	return nil
}

// ExpireProcessWindowsBefore is the COLD-STORAGE expiry horizon (P3.6): the
// point past which even the archive stops keeping process capture.
//
// It is the second of the arc's two horizons and the one that finally deletes.
// [observer.process].archive_days moves data here; [observer.process].
// retention_days — which today deletes outright at 30 days — becomes this
// file's own delete horizon instead, so the operator-visible change is
// "recoverable for 30 days, slower after 14" rather than "gone at 30".
//
// Returns the days it removed, for the retention report.
func (s *Store) ExpireProcessWindowsBefore(ctx context.Context, cutoffDay string, maxDays int) ([]string, error) {
	if cutoffDay == "" || maxDays <= 0 {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT DISTINCT substr(started_at, 1, 10) AS day FROM archive_process_runs
		  WHERE started_at < ?
		  UNION
		 SELECT DISTINCT substr(timestamp, 1, 10) FROM archive_process_events
		  WHERE timestamp < ?
		  ORDER BY day LIMIT ?`, cutoffDay, cutoffDay, maxDays)
	if err != nil {
		return nil, fmt.Errorf("archivestore.ExpireProcessWindowsBefore: list: %w", err)
	}
	var days []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("archivestore.ExpireProcessWindowsBefore: scan: %w", err)
		}
		days = append(days, d)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, fmt.Errorf("archivestore.ExpireProcessWindowsBefore: %w", err)
	}
	_ = rows.Close()

	for _, d := range days {
		if err := s.DeleteProcessWindow(ctx, archive.Window{Day: d}); err != nil {
			return nil, err
		}
	}
	return days, nil
}

// --- direct-read path (design §4.3) ----------------------------------
//
// The design's default for Bucket B is DIRECT READ WITH NO WRITE-BACK: a
// dashboard request for an archived session's process trail is answered from
// the archive file for that one request. Copying rows back would re-grow the
// hot database on a read — the exact thing the arc exists to stop — and give
// the live correlation sweep historical rows to reconsider, which it has no
// business doing. The operator confirmed this recommendation.
//
// Both readers below take the SAME predicate shape as their hot counterparts
// (session_id, plus event_type for the network view), so an archived session's
// panel is populated by the same question, asked of a different file.

// ProcessRunsForSession streams the archived process_runs rows for one session.
// Column-generic like everything else here; the caller decodes.
func (s *Store) ProcessRunsForSession(ctx context.Context, sessionID string, batchRows int, sink archive.WindowSink) error {
	if sessionID == "" {
		return nil
	}
	if batchRows <= 0 {
		batchRows = archive.DefaultBatchRows
	}
	return streamGeneric(ctx, s.db,
		`SELECT * FROM archive_process_runs WHERE session_id = ? ORDER BY started_at ASC, pid ASC`,
		[]any{sessionID}, "process_runs", batchRows, "archived_at", sink)
}

// HasArchivedSessionProcesses reports whether the archive holds any process
// rows for a session. One indexed lookup, LIMIT 1 — the cheap question a hot
// miss asks before paying for a full archived read.
func (s *Store) HasArchivedSessionProcesses(ctx context.Context, sessionID string) (bool, error) {
	if sessionID == "" {
		return false, nil
	}
	var one int
	err := s.db.QueryRowContext(ctx,
		`SELECT 1 FROM archive_process_runs WHERE session_id = ? LIMIT 1`, sessionID).Scan(&one)
	switch {
	case err == sql.ErrNoRows:
		return false, nil
	case err != nil:
		return false, fmt.Errorf("archivestore.HasArchivedSessionProcesses: %w", err)
	}
	return true, nil
}

// --- generic streaming ------------------------------------------------

// streamGeneric runs a query and hands the cursor to archive.StreamRows, the
// ONE batch-assembly implementation both sides of a verification share.
func streamGeneric(ctx context.Context, db *sql.DB, query string, args []any, table string, batchRows int, skipCol string, sink archive.WindowSink) error {
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("query: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return archive.StreamRows(ctx, rows, table, batchRows, skipCol, sink)
}
