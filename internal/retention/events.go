package retention

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// eventSweepRule describes ONE bounded, age-based sweep of a node-local
// append-only event table.
//
// This is a data table walked top-down (CLAUDE.md §5), deliberately not an
// if-ladder: every horizon this pass grows is one more row here plus one
// more field on EventSweepDays, and the delete mechanics (batching, the
// per-pass cap, the counting) are written once. Adding a row must never
// mean adding a branch.
type eventSweepRule struct {
	// Table is the node-local table this rule sweeps.
	Table string
	// TimeColumn is the RFC3339 TEXT column carrying the row's event time.
	// Both tables today spell it `timestamp`; the field exists so a future
	// row whose schema disagrees is a data change, not a code change.
	TimeColumn string
	// BatchSize bounds a single DELETE statement. The sweep issues at most
	// MaxBatchesPerPass of them, so the whole rule is bounded per pass.
	BatchSize int
	// Days resolves this rule's configured horizon out of the caller's
	// options. Zero (or negative) means keep forever.
	Days func(EventSweepDays) int
	// Note is the operator-facing reason this table has a horizon at all,
	// quoted in the returned EventSweepCounts key comments and in the docs.
	Note string
}

// EventSweepDays carries the configured per-table horizons, in days, that
// eventSweepRules resolve against. Zero on any field means keep forever —
// the same convention every other retention horizon in this package uses.
type EventSweepDays struct {
	// CompactionEventsDays is [observer.retention].compaction_events_days.
	CompactionEventsDays int
	// CompressionEventsDays is [observer.retention].compression_events_days.
	CompressionEventsDays int
}

// EventSweepCounts reports rows deleted per table by one sweepEventTables
// pass, keyed by table name.
//
// A table that WAS swept is always present, at 0 when nothing was eligible;
// a table whose horizon is disabled (keep forever) is ABSENT. "We did not
// sweep" and "we swept and found nothing" are different facts, and the map's
// key set is what distinguishes them.
type EventSweepCounts map[string]int

// Total returns the sum across every swept table, the single number the
// prune summary and the tick log print.
func (c EventSweepCounts) Total() int {
	var n int
	for _, v := range c {
		n += v
	}
	return n
}

// maxEventSweepBatchesPerPass bounds how many BatchSize-sized DELETEs one
// rule may issue in a single retention pass.
//
// This is the same posture as shrinkToCap's single-pass rule: retention runs
// on a live daemon, so a pass must have a known worst case rather than loop
// until the backlog is gone. With the defaults below that is 200k
// compaction_events rows and 500k compression_events rows per pass — far
// more than a day accumulates, so a healthy node drains its backlog in one
// pass and the cap only engages on the first sweep of a long-unpruned DB,
// which then drains over subsequent ticks instead of stalling the daemon.
const maxEventSweepBatchesPerPass = 100

// eventSweepRules is the ordered rule set. Order is presentation only —
// the rules are independent, each bounded on its own.
var eventSweepRules = []eventSweepRule{
	{
		Table:      "compaction_events",
		TimeColumn: "timestamp",
		// Small batch, very large rows: file_state_snapshot averages
		// ~900 KB and ghost_files_after ~240 KB on the live node
		// (1.4 GiB in 1,333 rows), so a 2k-row batch is already a
		// multi-GB statement's worth of freed pages.
		BatchSize: 2_000,
		Days:      func(d EventSweepDays) int { return d.CompactionEventsDays },
		Note:      "per-session compaction snapshots; the payload is a point-in-time file-state blob that stops being actionable once the session is long over",
	},
	{
		Table:      "compression_events",
		TimeColumn: "timestamp",
		// Small rows, very many of them (3.59M / 915 MB live), and
		// idx_compression_events_ts (migration 009) makes the cutoff
		// scan an index range — a larger batch is cheap here.
		BatchSize: 5_000,
		Days:      func(d EventSweepDays) int { return d.CompressionEventsDays },
		Note:      "one row per compression decision per turn; the aggregate savings view is served from api_turns, so the per-decision detail is a debugging tail",
	},
}

// sweepEventTables walks eventSweepRules and deletes, per rule, rows older
// than that rule's horizon — in bounded batches, respecting ctx between
// them.
//
// Each batch is its own statement (no surrounding transaction): these tables
// are append-only telemetry with no reader that needs a consistent snapshot
// across the sweep, and one long transaction over millions of rows is
// exactly the write-stall shape the 2026-08 incidents came from.
func (p *Pruner) sweepEventTables(ctx context.Context, days EventSweepDays) (EventSweepCounts, error) {
	counts := EventSweepCounts{}
	for _, rule := range eventSweepRules {
		horizon := rule.Days(days)
		if horizon <= 0 {
			continue // keep forever
		}
		cutoff := nowUTC().AddDate(0, 0, -horizon).Format(time.RFC3339Nano)
		n, err := p.deleteEventBatches(ctx, rule, cutoff)
		counts[rule.Table] = n
		if err != nil {
			return counts, err
		}
	}
	return counts, nil
}

// deleteEventBatches issues up to maxEventSweepBatchesPerPass bounded
// DELETEs for one rule, stopping early when a batch removes fewer rows than
// the batch size (the backlog is drained).
func (p *Pruner) deleteEventBatches(ctx context.Context, rule eventSweepRule, cutoff string) (int, error) {
	// The table and column names come from the package-private rule table
	// above, never from caller input, so this interpolation carries no
	// injection surface; SQLite will not bind an identifier as a parameter.
	//
	// Deliberately NO `ORDER BY <time>` on the inner select. Every row under
	// the cutoff is equally deletable, so ordering buys nothing — and
	// compaction_events has no index on `timestamp` at all (migration 001
	// created none; 015's idx_compaction_events_injected is partial on
	// injected_at), so an ORDER BY would make each of up to
	// maxEventSweepBatchesPerPass batches a full table scan plus a temp
	// b-tree sort over ~1 MB rows. Unordered, SQLite stops as soon as it has
	// found BatchSize matching rows.
	//nolint:gosec // G201: identifiers come from the package-private eventSweepRule table above, never caller input; the cutoff is bound.
	stmt := fmt.Sprintf(
		`DELETE FROM %s WHERE rowid IN (
		     SELECT rowid FROM %s WHERE %s < ? LIMIT %d)`,
		rule.Table, rule.Table, rule.TimeColumn, rule.BatchSize)

	var total int
	for i := 0; i < maxEventSweepBatchesPerPass; i++ {
		if err := ctx.Err(); err != nil {
			return total, fmt.Errorf("retention.sweepEventTables: %s: %w", rule.Table, err)
		}
		res, err := p.db.ExecContext(ctx, stmt, cutoff)
		if err != nil {
			if missingTable(err) {
				// A table a future build drops (or an older DB never
				// created) must not fail the whole retention pass.
				return total, nil
			}
			return total, fmt.Errorf("retention.sweepEventTables: %s: %w", rule.Table, err)
		}
		n, _ := res.RowsAffected()
		total += int(n)
		if int(n) < rule.BatchSize {
			break
		}
	}
	return total, nil
}

// missingTable reports whether err is SQLite's "no such table" — the one
// error class this sweep degrades to a no-op on.
func missingTable(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "no such table")
}
