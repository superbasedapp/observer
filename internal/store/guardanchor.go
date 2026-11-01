package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// guardAnchorUnprovenListMax caps GuardAnchorRepairReport.Unproven.
const guardAnchorUnprovenListMax = 20

// GuardAnchorRepairOptions selects what RepairGuardAnchors does.
type GuardAnchorRepairOptions struct {
	// Apply writes the proven anchors; false only reports.
	Apply bool
	// Ceiling is the highest action id tried. 0 means the highest id the
	// node ever issued for an action (sqlite_sequence; actions ids are
	// AUTOINCREMENT, so never reused).
	Ceiling int64
}

// GuardAnchorRepairReport is the result of RepairGuardAnchors.
type GuardAnchorRepairReport struct {
	// Candidates is the number of rows that fail verification as rewritten
	// rows and carry no action id at all (action_id and action_anchor both
	// NULL): the shape maintenance left before agent migration 197.
	Candidates int
	// Proven is the number of candidates whose stored chain_hash one action
	// id reproduces, every other column as stored.
	Proven int
	// Unproven lists the first candidate ids no action id in [1, Ceiling]
	// reproduced (at most guardAnchorUnprovenListMax); UnprovenCount counts
	// all of them. Those rows stay reported by verify-audit.
	Unproven      []int64
	UnprovenCount int
	// Ceiling is the highest action id tried.
	Ceiling int64
	// Tries is the number of candidate hashes computed.
	Tries int64
	// Repaired is the number of rows whose action_anchor was written
	// (Apply only).
	Repaired int
	// Applied is true when the proven anchors were written.
	Applied bool
}

// guardAnchorFix is one proven repair: row id and the action id that
// reproduces its stored hash.
type guardAnchorFix struct {
	id, anchor int64
}

// RepairGuardAnchors restores the action id of guard_events rows whose
// action_id maintenance cleared before agent migration 197 (ledger
// GUARD-CHAIN-1). Such a row hashes to a value its stored columns no longer
// reproduce, so verify-audit reports it as a rewritten row.
//
// The repair is a proof, not a judgement: for each such row it tries action
// ids and accepts one only when SHA-256(chain_prev || 0x1e || canonical
// bytes with that id) equals the row's stored chain_hash, every other column
// exactly as stored. A row edited in any other way reproduces no hash and is
// left as it is; no chain_prev or chain_hash is ever rewritten, so a broken
// link (a deleted row) stays reported. The only column written is
// action_anchor, and only where it and action_id are both NULL.
//
// The search runs outside any write transaction; Apply then takes the write
// lock and re-proves each row inside it before writing, so a row that
// changed in between is skipped.
func (s *Store) RepairGuardAnchors(ctx context.Context, opts GuardAnchorRepairOptions) (GuardAnchorRepairReport, error) {
	report := GuardAnchorRepairReport{Ceiling: opts.Ceiling}
	if report.Ceiling <= 0 {
		ceiling, err := s.actionIDCeiling(ctx)
		if err != nil {
			return report, err
		}
		report.Ceiling = ceiling
	}

	rows, err := s.db.QueryContext(ctx, guardEventSelectColumns+` ORDER BY id ASC`)
	if err != nil {
		return report, fmt.Errorf("store.RepairGuardAnchors: query: %w", err)
	}
	all, err := loadGuardEventRows(rows, "store.RepairGuardAnchors")
	if err != nil {
		return report, err
	}

	var fixes []guardAnchorFix
	hint := int64(1)
	for i := range all {
		r := &all[i]
		if id := r.hashedActionID(); id != nil {
			hint = *id
			continue
		}
		if guardChainHash(r.ChainPrev, r.canonicalBytes()) == r.ChainHash {
			continue // an action-less row that verifies (a hook verdict)
		}
		report.Candidates++
		anchor, ok := proveGuardAnchor(r, hint, report.Ceiling, &report.Tries)
		if !ok {
			report.UnprovenCount++
			if len(report.Unproven) < guardAnchorUnprovenListMax {
				report.Unproven = append(report.Unproven, r.ID)
			}
			continue
		}
		report.Proven++
		fixes = append(fixes, guardAnchorFix{id: r.ID, anchor: anchor})
		hint = anchor
	}
	if !opts.Apply || len(fixes) == 0 {
		return report, nil
	}
	n, err := s.writeGuardAnchors(ctx, fixes)
	if err != nil {
		return report, err
	}
	report.Repaired = n
	report.Applied = true
	return report, nil
}

// proveGuardAnchor searches action ids outward from hint (hint, hint+1,
// hint-1, ...) within [1, ceiling] for the one whose canonical bytes hash
// to r's stored chain_hash. r's anchor is left unset.
func proveGuardAnchor(r *GuardEventRow, hint, ceiling int64, tries *int64) (int64, bool) {
	if ceiling < 1 {
		return 0, false
	}
	hint = min(max(hint, 1), ceiling)
	defer func() { r.actionAnchor = nil }()
	try := func(id int64) bool {
		*tries++
		r.actionAnchor = &id
		return guardChainHash(r.ChainPrev, r.canonicalBytes()) == r.ChainHash
	}
	for d := int64(0); ; d++ {
		up, down := hint+d, hint-d
		if up > ceiling && down < 1 {
			return 0, false
		}
		if up <= ceiling && try(up) {
			return up, true
		}
		if d > 0 && down >= 1 && try(down) {
			return down, true
		}
	}
}

// actionIDCeiling is the highest action id this node ever issued.
func (s *Store) actionIDCeiling(ctx context.Context) (int64, error) {
	var ceiling int64
	err := s.db.QueryRowContext(ctx, `
		SELECT MAX(
		    COALESCE((SELECT seq FROM sqlite_sequence WHERE name = 'actions'), 0),
		    COALESCE((SELECT MAX(id) FROM actions), 0),
		    COALESCE((SELECT MAX(action_anchor) FROM guard_events), 0))`).Scan(&ceiling)
	if err != nil {
		return 0, fmt.Errorf("store.RepairGuardAnchors: ceiling: %w", err)
	}
	return ceiling, nil
}

// writeGuardAnchors re-proves and writes each fix in one write transaction
// and returns how many rows it wrote.
func (s *Store) writeGuardAnchors(ctx context.Context, fixes []guardAnchorFix) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store.RepairGuardAnchors: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	// Take the write lock first (the DedupGuardEvents pattern): no writer
	// can change a row between its re-proof and its update.
	if _, err := tx.ExecContext(ctx,
		`UPDATE schema_meta SET value = value WHERE key = ?`, guardChainCheckpointKey); err != nil {
		return 0, fmt.Errorf("store.RepairGuardAnchors: lock: %w", err)
	}
	upd, err := tx.PrepareContext(ctx,
		`UPDATE guard_events SET action_anchor = ? WHERE id = ? AND action_id IS NULL AND action_anchor IS NULL`)
	if err != nil {
		return 0, fmt.Errorf("store.RepairGuardAnchors: prepare: %w", err)
	}
	defer upd.Close()
	written := 0
	for _, f := range fixes {
		r, err := scanGuardEventRow(tx.QueryRowContext(ctx, guardEventSelectColumns+` WHERE id = ?`, f.id))
		if errors.Is(err, sql.ErrNoRows) {
			continue // the row is gone (a prune or dedup in between)
		}
		if err != nil {
			return 0, fmt.Errorf("store.RepairGuardAnchors: reload %d: %w", f.id, err)
		}
		if r.hashedActionID() != nil {
			continue
		}
		anchor := f.anchor
		r.actionAnchor = &anchor
		if guardChainHash(r.ChainPrev, r.canonicalBytes()) != r.ChainHash {
			continue
		}
		res, err := upd.ExecContext(ctx, f.anchor, f.id)
		if err != nil {
			return 0, fmt.Errorf("store.RepairGuardAnchors: update %d: %w", f.id, err)
		}
		if n, _ := res.RowsAffected(); n > 0 {
			written++
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store.RepairGuardAnchors: commit: %w", err)
	}
	return written, nil
}
