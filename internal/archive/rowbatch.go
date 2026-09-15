package archive

import (
	"context"
	"fmt"
	"time"
)

// This file carries Bucket B — process capture — of the corpus archival arc
// (docs/plans/observer-corpus-archival-lazyload-design-2026-08-26.md §2.2, P3).
//
// WHY THIS BUCKET USES A GENERIC ROW SHAPE WHILE BUCKET A USES TYPED STRUCTS.
// Bucket A's six codeintel tables total 40-odd columns and are REGENERABLE: a
// transcription slip costs a re-index. Bucket B is 94 columns across three
// tables (process_runs alone has 56 after migration 045) and is the ONLY-COPY
// bucket — there is no repository to re-derive live eBPF/ETW capture from. Hand-
// transcribing 94 columns into six places each (struct, digest, hot export scan,
// archive insert, archive read scan, direct-read scan) is ~560 opportunities for
// a silent column misalignment, in the one bucket where a silent misalignment is
// unrecoverable.
//
// So the column list has exactly ONE source of truth: the hot table itself, read
// back from the driver via rows.Columns(). Values move as driver values and are
// written by NAME, so column ORDER cannot drift, an added column is carried
// automatically, and a column the archive schema lacks fails LOUDLY at copy time
// — before anything is deleted — instead of being quietly dropped.
//
// The verification math is unchanged: [VerifyWindow] is a thin adapter over
// [VerifyTables], the same primitive Bucket A's delete is gated on.

// ProcessTables is the archive fan-out for Bucket B, PARENT-FIRST.
//
// Order is load-bearing on the write side (process_events references
// process_runs, process_network_bodies references process_events) and is
// reversed for deletes. It is a package-level list so both directions and the
// digest walk the same table set — a table added to one and forgotten in
// another is the shape that strands only-copy rows.
var ProcessTables = []string{
	"process_runs",
	"process_events",
	"process_network_bodies",
}

// Window is one archivable slice of process capture: a single UTC day.
//
// A DAY, NOT A SESSION — the deviation-D2 question P3 had to answer. Three
// facts forced it:
//
//   - process_network_bodies carries no session_id at all, and
//     process_events.session_id is stamped once at insert and never
//     re-attributed, so it can be empty or stale for rows whose run was
//     correlated later. A session-keyed archive would silently strand exactly
//     the unattributed capture that `capture_unattributed` exists to collect.
//   - The horizon this replaces (store.PruneProcessRows) is already time-based
//     and sweeps runs and events on two INDEPENDENT clocks. Archiving must move
//     the same set that delete would have removed, or the two disagree about
//     what "cold" means — the same reason Bucket A reuses the staleness query
//     rather than inventing a second one.
//   - A day is bounded and enumerable; a session is neither (a long session
//     straddles horizons).
type Window struct {
	// Day is the UTC calendar day, "YYYY-MM-DD".
	Day string
}

// Bounds returns the half-open [lo, hi) string range that selects the window's
// rows from a RFC3339Nano-UTC text timestamp column.
//
// Prefix comparison rather than parsed dates: every process timestamp is
// written by store.timestamp as RFC3339Nano in UTC, so lexicographic ordering
// IS chronological ordering, and a plain range predicate can ride an index on
// the raw column. A substr()/date() predicate could not.
func (w Window) Bounds() (lo, hi string) {
	return w.Day, w.nextDay()
}

func (w Window) nextDay() string {
	t, err := time.Parse("2006-01-02", w.Day)
	if err != nil {
		// An unparseable day selects nothing rather than everything: the
		// fail-open direction for a delete-bearing predicate is "move no
		// rows", never "move all rows".
		return w.Day
	}
	return t.AddDate(0, 0, 1).Format("2006-01-02")
}

// Valid reports whether the day parses and yields a non-empty range.
func (w Window) Valid() bool {
	if w.Day == "" {
		return false
	}
	_, err := time.Parse("2006-01-02", w.Day)
	return err == nil
}

// WindowCandidate is one window eligible to move, with the shape guard that
// makes a concurrent write cancel the move.
type WindowCandidate struct {
	// Window is the day.
	Window Window
	// Rows is the total hot row count across [ProcessTables] at selection
	// time.
	Rows int64
}

// WindowShape is the guard the hot delete re-checks inside its own
// transaction. It is Bucket B's analogue of Bucket A's (watermark, file count)
// pair, and it has to be richer for one reason: process_runs rows MUTATE.
// store.PersistRuns upserts on process_key, refreshing last_seen_at and the
// exit/metric columns of a run that started days ago, so a row count and a
// MAX(id) alone would report "unchanged" while the row's contents moved on.
// MaxLastSeen catches that.
//
// process_events and process_network_bodies are insert-only, and a body row is
// only ever written in the same transaction as its event, so the event
// count+MAX(id) pair covers the bodies too.
type WindowShape struct {
	Runs        int64
	MaxRunID    int64
	MaxLastSeen string
	Events      int64
	MaxEventID  int64
	Bodies      int64
}

// Equal reports whether two shapes describe the same hot state.
func (s WindowShape) Equal(o WindowShape) bool { return s == o }

// Empty reports whether the window holds no rows at all.
func (s WindowShape) Empty() bool { return s.Runs == 0 && s.Events == 0 && s.Bodies == 0 }

// TotalRows is the window's total hot row count.
func (s WindowShape) TotalRows() int64 { return s.Runs + s.Events + s.Bodies }

// WindowCompletion carries what the hot side needs to finish one Bucket B move
// atomically. It mirrors [Completion]'s role for Bucket A.
type WindowCompletion struct {
	// Window is the day being archived.
	Window Window
	// ExpectedShape is the guard captured before the copy. The delete
	// re-reads it inside its own transaction and refuses if it moved.
	ExpectedShape WindowShape
	// ArchivedAt is the completion timestamp (unix seconds).
	ArchivedAt int64
	// RowsArchived is the VERIFIED cold row count recorded on the marker.
	RowsArchived int64
}

// WindowMarker is one process_archived_windows row.
type WindowMarker struct {
	// Day is the UTC day the window covers.
	Day string
	// ArchivedAt is when the move completed (unix seconds).
	ArchivedAt int64
	// Runs, Events, Bodies are the per-table verified cold counts, so the
	// aggregate storage surface can report what moved without opening the
	// archive file.
	Runs, Events, Bodies int64
}

// RowsArchived is the marker's total row count.
func (m WindowMarker) RowsArchived() int64 { return m.Runs + m.Events + m.Bodies }

// RowBatch is a bounded slab of rows from ONE table, carrying the column names
// the driver reported alongside the values.
//
// Cols travels with the batch rather than being assumed by the reader because
// it is the whole point: the writer inserts BY NAME, so the hot table's own
// column list — not a hand-maintained copy of it — decides what is archived.
type RowBatch struct {
	// Table is the HOT table name (never the archive_-prefixed one; the
	// archive side derives its own).
	Table string
	// Cols are the column names, in the order Vals are ordered.
	Cols []string
	// Vals is one slice of driver values per row, each len(Cols) long.
	Vals [][]any
}

// WindowSink receives a window's rows in bounded batches, parent-first.
type WindowSink interface {
	WriteRows(ctx context.Context, b RowBatch) error
}

// WindowDigest fingerprints one window: one [TableDigest] per table in
// [ProcessTables].
type WindowDigest struct {
	byTable map[string]*TableDigest
}

// NewWindowDigest returns a zeroed digest with an entry per archived table, so
// a table that produced no rows is still COMPARED (as zero) rather than being
// absent from one side and silently skipped.
func NewWindowDigest() *WindowDigest {
	d := &WindowDigest{byTable: make(map[string]*TableDigest, len(ProcessTables))}
	for _, t := range ProcessTables {
		d.byTable[t] = &TableDigest{}
	}
	return d
}

// Add folds one batch into the digest.
func (d *WindowDigest) Add(b RowBatch) error {
	td, ok := d.byTable[b.Table]
	if !ok {
		return fmt.Errorf("archive: batch for unknown table %q", b.Table)
	}
	for _, row := range b.Vals {
		td.Add(rowDigest(b.Cols, row))
	}
	return nil
}

// Tables renders the digest as the positional list [VerifyTables] compares,
// always in [ProcessTables] order so both sides line up by construction.
func (d *WindowDigest) Tables() []NamedTable {
	out := make([]NamedTable, 0, len(ProcessTables))
	for _, t := range ProcessTables {
		var td TableDigest
		if v, ok := d.byTable[t]; ok && v != nil {
			td = *v
		}
		out = append(out, NamedTable{Name: t, Digest: td})
	}
	return out
}

// TotalRows is the window's digested row count.
func (d *WindowDigest) TotalRows() int64 {
	var n int64
	for _, t := range d.Tables() {
		n += t.Digest.Rows
	}
	return n
}

// Rows reports one table's digested row count.
func (d *WindowDigest) Rows(table string) int64 {
	if v, ok := d.byTable[table]; ok && v != nil {
		return v.Rows
	}
	return 0
}

// Empty reports whether the window digested no rows.
func (d *WindowDigest) Empty() bool { return d.TotalRows() == 0 }

// VerifyWindow is Bucket B's gate. It is a THIN ADAPTER over [VerifyTables] —
// the identical count+checksum comparison Bucket A's delete is gated on, which
// P1 proved load-bearing with four separate mutation proofs. Bucket B, the
// only-copy bucket, deliberately inherits that implementation rather than
// getting one of its own.
func VerifyWindow(hot, cold *WindowDigest) error {
	if hot == nil || cold == nil {
		return fmt.Errorf("%w: a digest was missing entirely", ErrDigestMismatch)
	}
	return VerifyTables(hot.Tables(), cold.Tables())
}

// windowDigestSink accumulates a [WindowDigest] and writes nothing.
type windowDigestSink struct{ d *WindowDigest }

// NewWindowDigestSink returns a [WindowSink] that only fingerprints.
func NewWindowDigestSink() interface {
	WindowSink
	Digest() *WindowDigest
} {
	return &windowDigestSink{d: NewWindowDigest()}
}

func (s *windowDigestSink) Digest() *WindowDigest { return s.d }

func (s *windowDigestSink) WriteRows(_ context.Context, b RowBatch) error { return s.d.Add(b) }

// windowTeeSink fans one export into a primary sink and a digest, so the
// fingerprint of what was copied comes from the SAME pass that copied it.
type windowTeeSink struct {
	primary WindowSink
	d       *WindowDigest
}

// NewWindowTeeSink returns a [WindowSink] forwarding to primary while
// fingerprinting everything that passes through.
func NewWindowTeeSink(primary WindowSink) interface {
	WindowSink
	Digest() *WindowDigest
} {
	return &windowTeeSink{primary: primary, d: NewWindowDigest()}
}

func (s *windowTeeSink) Digest() *WindowDigest { return s.d }

// WriteRows DIGESTS FIRST, then forwards.
//
// The order is load-bearing. A batch carries slices, and the primary sink is
// free to touch them — a writer that normalizes, trims or reuses a value in
// place would otherwise have its edit folded into the "hot" digest, which would
// then match the cold copy of that same edit and verify a corruption into
// existence. Fingerprinting before the batch leaves this function pins the
// digest to what the EXPORTER read out of the hot table, which is the thing the
// cold read-back is supposed to reproduce.
func (s *windowTeeSink) WriteRows(ctx context.Context, b RowBatch) error {
	if err := s.d.Add(b); err != nil {
		return err
	}
	return s.primary.WriteRows(ctx, b)
}

// Rows is the read cursor [StreamRows] walks. *sql.Rows satisfies it
// STRUCTURALLY, so the hot store and the archive store share one streaming
// implementation without this package importing database/sql — the purity its
// imports_test.go pins.
//
// One implementation matters more here than it usually would: the hot side and
// the cold side of a verification must produce identically-shaped batches, and
// two copies of "read the columns, drop the bookkeeping one, batch the values"
// is precisely where they would drift apart into a mismatch with no data
// problem behind it.
type Rows interface {
	Columns() ([]string, error)
	Next() bool
	Scan(dest ...any) error
	Err() error
}

// StreamRows reads a cursor's rows as generic column-name/value batches and
// pushes them through sink in bounded slabs.
//
// skipCol, when non-empty, drops that column from every batch. The archive
// tables carry an archived_at column the hot tables do not; dropping it on the
// cold read is what makes a cold batch EXACTLY a hot batch — comparable by the
// same digest, and writable straight back into the hot table on a rehydrate.
func StreamRows(ctx context.Context, rows Rows, table string, batchRows int, skipCol string, sink WindowSink) error {
	if batchRows <= 0 {
		batchRows = DefaultBatchRows
	}
	allCols, err := rows.Columns()
	if err != nil {
		return fmt.Errorf("archive.StreamRows(%s): columns: %w", table, err)
	}
	keep := make([]int, 0, len(allCols))
	cols := make([]string, 0, len(allCols))
	for i, c := range allCols {
		if skipCol != "" && c == skipCol {
			continue
		}
		keep = append(keep, i)
		cols = append(cols, c)
	}

	batch := RowBatch{Table: table, Cols: cols}
	flush := func() error {
		if len(batch.Vals) == 0 {
			return nil
		}
		if err := sink.WriteRows(ctx, batch); err != nil {
			return err
		}
		batch.Vals = nil
		return nil
	}
	for rows.Next() {
		raw := make([]any, len(allCols))
		ptrs := make([]any, len(allCols))
		for i := range raw {
			ptrs[i] = &raw[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return fmt.Errorf("archive.StreamRows(%s): scan: %w", table, err)
		}
		vals := make([]any, 0, len(keep))
		for _, i := range keep {
			vals = append(vals, NormalizeValue(raw[i]))
		}
		batch.Vals = append(batch.Vals, vals)
		if len(batch.Vals) >= batchRows {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("archive.StreamRows(%s): rows: %w", table, err)
	}
	return flush()
}

// NormalizeValue collapses the two representations a SQLite driver may hand
// back for a TEXT column — []byte and string — into one.
//
// Without it a digest would compare []byte("x") on one side against "x" on the
// other: different type tags, different hashes, a verification failure with no
// data problem behind it. Normalizing at the single point where driver values
// enter the arc keeps that from becoming a per-table workaround.
//
// Safe for the Bucket B tables specifically because none of them declares a
// BLOB column (agent migrations 044/045/067 are TEXT and INTEGER throughout),
// so a []byte here is always a TEXT rendering and never binary payload. A
// future BLOB column in an archived table would need this revisited.
func NormalizeValue(v any) any {
	if b, ok := v.([]byte); ok {
		return string(b)
	}
	return v
}
