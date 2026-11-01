package retention

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// holdcap.go is the held-data ceiling of the org push hold (T-839 / D-673:
// "hold unsent data whenever enrolled, paused or not, up to a size cap of
// about 2 GB, and warn at the cap").
//
// An enrolled node never deletes a row the org has not accepted, so a push
// that is paused, refused forever (a permanently rejected batch, a revoked
// enrolment, a server answering 503 for weeks) would otherwise grow the local
// database until the disk fills. PushHold.MaxHeldBytes bounds that: when the
// ESTIMATED bytes of the held rows pass the cap, the oldest held rows across
// every held table are released to the normal age pass, newest-first
// accumulation deciding exactly how many, so the held set is brought back to
// the cap and no further. Releasing unsent rows is data loss for the org, so
// the caller logs it at ERROR and records it for `observer doctor`.
//
// The byte figure is an ESTIMATE: the stored length of each held row's
// variable-length columns plus a fixed per-row overhead. It deliberately does
// not walk dbstat (a full-file scan on a many-GB database) and does not count
// index or FTS pages, so the real on-disk footprint of the held rows is
// somewhat larger. "About 2 GB" is the operator ruling's own wording.

// The literal 96 in both size expressions approximates the fixed cost of one
// stored row (rowid, integer columns, record header, short hashes) beyond the
// variable-length text columns they sum.

// actionHeldBytesExpr estimates one actions row's stored bytes: the
// variable-length columns that carry content, measured in bytes (CAST AS BLOB
// so a multi-byte character counts as its encoded length).
const actionHeldBytesExpr = `(96
   + COALESCE(LENGTH(CAST(target AS BLOB)), 0)
   + COALESCE(LENGTH(CAST(raw_tool_input AS BLOB)), 0)
   + COALESCE(LENGTH(CAST(raw_tool_output AS BLOB)), 0)
   + COALESCE(LENGTH(CAST(preceding_reasoning AS BLOB)), 0)
   + COALESCE(LENGTH(CAST(error_message AS BLOB)), 0)
   + COALESCE(LENGTH(CAST(metadata AS BLOB)), 0)
   + COALESCE(LENGTH(CAST(user_attachments AS BLOB)), 0)
   + COALESCE(LENGTH(CAST(source_file AS BLOB)), 0))`

// guardHeldBytesExpr estimates one guard_events row's stored bytes.
const guardHeldBytesExpr = `(96
   + COALESCE(LENGTH(CAST(reason AS BLOB)), 0)
   + COALESCE(LENGTH(CAST(target_excerpt AS BLOB)), 0)
   + COALESCE(LENGTH(CAST(taint_origin AS BLOB)), 0)
   + COALESCE(LENGTH(CAST(chain_prev AS BLOB)), 0)
   + COALESCE(LENGTH(CAST(chain_hash AS BLOB)), 0))`

// heldRowsUnion selects every HELD row of every held, size-capped table: aged
// past that table's horizon and above that table's push cursor. One row per
// table in the union is one row of the table this file's comment names; a new
// cursor-pushed table that retention ages is one more UNION ALL arm here.
// Args: actions cutoff, actions cursor, guard cutoff, guard cursor. An empty
// cutoff selects nothing for that table (every stored timestamp is non-empty).
const heldRowsUnion = `
SELECT 'actions' AS tbl, id, timestamp AS ts, ` + actionHeldBytesExpr + ` AS sz
  FROM actions WHERE timestamp < ? AND id > ?
UNION ALL
SELECT 'guard_events' AS tbl, id, ts, ` + guardHeldBytesExpr + ` AS sz
  FROM guard_events WHERE ts < ? AND id > ?`

// HoldCap reports the held-data ceiling for one pass (T-839).
type HoldCap struct {
	// CapBytes is PushHold.MaxHeldBytes (0 = no ceiling).
	CapBytes int64 `json:"cap_bytes"`
	// HeldBytes is the estimated bytes of every held row BEFORE any shed.
	HeldBytes int64 `json:"held_bytes"`
	// ShedThrough is the timestamp at or before which held rows were
	// released this pass because HeldBytes passed CapBytes; "" when nothing
	// was released.
	ShedThrough string `json:"shed_through,omitempty"`
	// ShedActions / ShedGuardEvents count the held rows released, per table.
	ShedActions     int64 `json:"shed_actions,omitempty"`
	ShedGuardEvents int64 `json:"shed_guard_events,omitempty"`
}

// Shed reports whether the pass released held (unsent) rows.
func (h HoldCap) Shed() bool { return h.ShedActions+h.ShedGuardEvents > 0 }

// heldCutoffs returns the per-table age cutoffs the hold applies to; "" for a
// table whose horizon is off (nothing of it is ever aged, so nothing is held).
func heldCutoffs(maxAgeDays int, hold *PushHold) (actions, guard string) {
	now := nowUTC()
	if maxAgeDays > 0 {
		actions = now.AddDate(0, 0, -maxAgeDays).Format(time.RFC3339Nano)
	}
	if hold.GuardMaxAgeDays > 0 {
		guard = now.Add(-time.Duration(hold.GuardMaxAgeDays) * 24 * time.Hour).Format(time.RFC3339Nano)
	}
	return actions, guard
}

// EstimateHold measures the held rows against the ceiling WITHOUT deleting
// anything: HeldBytes, and the ShedThrough / Shed* a pass run now would
// apply. A nil hold, or no horizon on any held table, holds nothing.
func EstimateHold(ctx context.Context, database *sql.DB, maxAgeDays int, hold *PushHold) (HoldCap, error) {
	if hold == nil || database == nil {
		return HoldCap{}, nil
	}
	hc := HoldCap{CapBytes: hold.MaxHeldBytes}
	aCut, gCut := heldCutoffs(maxAgeDays, hold)
	if aCut == "" && gCut == "" {
		return hc, nil
	}
	args := []any{aCut, hold.ActionsCursor, gCut, hold.GuardEventsCursor}
	if err := database.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(sz), 0) FROM (`+heldRowsUnion+`)`, args...).Scan(&hc.HeldBytes); err != nil {
		return hc, fmt.Errorf("retention.EstimateHold: held bytes: %w", err)
	}
	if hold.MaxHeldBytes <= 0 || hc.HeldBytes <= hold.MaxHeldBytes {
		return hc, nil
	}
	// Accumulate newest first; every row whose running total passes the cap
	// is an OLDEST held row beyond the ceiling and is released.
	rows, err := database.QueryContext(ctx, `
SELECT tbl, COUNT(*), MAX(ts) FROM (
  SELECT tbl, ts, SUM(sz) OVER (ORDER BY ts DESC, tbl DESC, id DESC
                                ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) AS cum
    FROM (`+heldRowsUnion+`)
) WHERE cum > ? GROUP BY tbl`, append(args, hold.MaxHeldBytes)...)
	if err != nil {
		return hc, fmt.Errorf("retention.EstimateHold: shed plan: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var tbl, maxTS string
		var n int64
		if err := rows.Scan(&tbl, &n, &maxTS); err != nil {
			return hc, fmt.Errorf("retention.EstimateHold: shed plan scan: %w", err)
		}
		switch tbl {
		case "actions":
			hc.ShedActions = n
		case "guard_events":
			hc.ShedGuardEvents = n
		}
		if maxTS > hc.ShedThrough {
			hc.ShedThrough = maxTS
		}
	}
	if err := rows.Err(); err != nil {
		return hc, fmt.Errorf("retention.EstimateHold: shed plan rows: %w", err)
	}
	return hc, nil
}

// guardKeepFrom is the smallest guard_events id the guard sweep must keep
// under hold: the push cursor plus one, raised past every held row the
// ceiling released (ts at or before hold.shedThrough). The guard sweep prunes
// a chain PREFIX, so this is a floor, not a set.
func guardKeepFrom(ctx context.Context, database *sql.DB, hold *PushHold) (int64, error) {
	floor := hold.GuardEventsCursor
	if hold.shedThrough != "" {
		var m sql.NullInt64
		if err := database.QueryRowContext(ctx,
			`SELECT MAX(id) FROM guard_events WHERE id > ? AND ts <= ?`, floor, hold.shedThrough).Scan(&m); err != nil {
			return 0, fmt.Errorf("retention: guard keep floor: %w", err)
		}
		if m.Valid && m.Int64 > floor {
			floor = m.Int64
		}
	}
	return floor + 1, nil
}
