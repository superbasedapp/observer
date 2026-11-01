package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// GuardDedupReport is the result of DedupGuardEvents.
type GuardDedupReport struct {
	// Duplicates is the number of repeated watcher-path rows found (and,
	// when Applied, deleted).
	Duplicates int
	// ByTool counts Duplicates per tool.
	ByTool map[string]int
	// FirstDuplicateID is the lowest duplicate id: every row from here on
	// is re-hashed (0 when there are none).
	FirstDuplicateID int64
	// Rehashed is the number of surviving rows whose chain link was
	// rewritten.
	Rehashed int
	// Applied is true when the rows were deleted (and, unless KeepHashes,
	// the chain re-hashed).
	Applied bool
	// KeptHashes echoes GuardDedupOptions.KeepHashes: the rows were (or
	// would be) deleted with every stored hash left as it was.
	KeptHashes bool
	// Refused is non-empty when the cleanup was refused, and says why.
	Refused string
}

// guardDuplicateSQL selects every repeated watcher-path guard_events row: a
// row with an action anchor whose (action, rule, kind, decision, enforced,
// target) matches an earlier row. The oldest copy is the original; the
// rest came from a re-parse that re-evaluated an already-stored action
// (insertSingleAction's update branch, fixed 2026-10-21). Hook rows
// (action_id NULL) are never touched: two hook calls are two real events.
const guardDuplicateSQL = `
	SELECT id, COALESCE(tool, '') FROM (
	    SELECT id, tool, ROW_NUMBER() OVER (
	        PARTITION BY action_id, rule_id, COALESCE(event_kind, ''),
	                     COALESCE(decision, ''), enforced, COALESCE(target_hash, '')
	        ORDER BY id) AS n
	    FROM guard_events WHERE action_id IS NOT NULL)
	WHERE n > 1 ORDER BY id`

// GuardDedupOptions selects what DedupGuardEvents does.
type GuardDedupOptions struct {
	// Apply deletes; false only reports.
	Apply bool
	// KeepHashes deletes the repeats and rewrites no hash: each deletion
	// leaves a broken link that VerifyGuardChain reports. For a chain that
	// already fails verification inside the range a re-hash would cover,
	// where the re-hash is refused.
	KeepHashes bool
}

// DedupGuardEvents removes the repeated watcher-path guard_events rows and,
// unless opts.KeepHashes, re-hashes the chain from the first removed row
// onward, so the deletion leaves no break of its own. Without opts.Apply it
// only reports.
//
// The re-hash rewrites chain links, so it is refused when any row in the
// range it would rewrite already fails verification: re-hashing would hide
// that break. Rows before the first duplicate are never read or changed,
// and a break there stays exactly as VerifyGuardChain reports it. Runs in
// one write transaction taken before any read, so a concurrent writer (a
// hook process) waits or fails cleanly and can never append onto a link
// this rewrite replaces.
func (s *Store) DedupGuardEvents(ctx context.Context, opts GuardDedupOptions) (GuardDedupReport, error) {
	report := GuardDedupReport{ByTool: map[string]int{}, KeptHashes: opts.KeepHashes}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return report, fmt.Errorf("store.DedupGuardEvents: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	// Take the write lock first: a write statement, even one that matches
	// nothing, makes this the only writer until commit.
	if _, err := tx.ExecContext(ctx,
		`UPDATE schema_meta SET value = value WHERE key = ?`, guardChainCheckpointKey); err != nil {
		return report, fmt.Errorf("store.DedupGuardEvents: lock: %w", err)
	}

	dupIDs, err := guardDuplicateIDs(ctx, tx, &report)
	if err != nil {
		return report, err
	}
	if len(dupIDs) == 0 {
		return report, nil
	}
	if opts.KeepHashes {
		if !opts.Apply {
			return report, nil
		}
		if err := deleteGuardRows(ctx, tx, dupIDs); err != nil {
			return report, err
		}
		if err := tx.Commit(); err != nil {
			return report, fmt.Errorf("store.DedupGuardEvents: commit: %w", err)
		}
		report.Applied = true
		return report, nil
	}

	anchor, err := guardAnchorBefore(ctx, tx, report.FirstDuplicateID)
	if err != nil {
		return report, err
	}
	suffix, err := loadGuardEventRowsTx(ctx, tx, report.FirstDuplicateID)
	if err != nil {
		return report, err
	}
	if id, why := firstSuffixBreak(anchor, suffix); id != 0 {
		report.Refused = fmt.Sprintf("the audit chain is already broken at id %d (%s), inside the range a cleanup would re-hash; re-hashing would hide it", id, why)
		return report, nil
	}
	if !opts.Apply {
		return report, nil
	}
	if err := deleteGuardRows(ctx, tx, dupIDs); err != nil {
		return report, err
	}

	upd, err := tx.PrepareContext(ctx,
		`UPDATE guard_events SET chain_prev = ?, chain_hash = ? WHERE id = ?`)
	if err != nil {
		return report, fmt.Errorf("store.DedupGuardEvents: prepare rehash: %w", err)
	}
	defer upd.Close()
	prev := anchor
	for i := range suffix {
		r := &suffix[i]
		if _, gone := dupIDs[r.ID]; gone {
			continue
		}
		hash := guardChainHash(prev, r.canonicalBytes())
		if r.ChainPrev != prev || r.ChainHash != hash {
			if _, err := upd.ExecContext(ctx, prev, hash, r.ID); err != nil {
				return report, fmt.Errorf("store.DedupGuardEvents: rehash %d: %w", r.ID, err)
			}
			report.Rehashed++
		}
		prev = hash
	}
	if err := tx.Commit(); err != nil {
		return report, fmt.Errorf("store.DedupGuardEvents: commit: %w", err)
	}
	report.Applied = true
	return report, nil
}

// deleteGuardRows deletes the given guard_events ids inside tx.
func deleteGuardRows(ctx context.Context, tx *sql.Tx, ids map[int64]struct{}) error {
	del, err := tx.PrepareContext(ctx, `DELETE FROM guard_events WHERE id = ?`)
	if err != nil {
		return fmt.Errorf("store.DedupGuardEvents: prepare delete: %w", err)
	}
	defer del.Close()
	for id := range ids {
		if _, err := del.ExecContext(ctx, id); err != nil {
			return fmt.Errorf("store.DedupGuardEvents: delete %d: %w", id, err)
		}
	}
	return nil
}

// guardDuplicateIDs returns the duplicate ids as a set and fills the
// report's counts and first id.
func guardDuplicateIDs(ctx context.Context, tx *sql.Tx, report *GuardDedupReport) (map[int64]struct{}, error) {
	rows, err := tx.QueryContext(ctx, guardDuplicateSQL)
	if err != nil {
		return nil, fmt.Errorf("store.DedupGuardEvents: find duplicates: %w", err)
	}
	defer rows.Close()
	ids := map[int64]struct{}{}
	for rows.Next() {
		var id int64
		var tool string
		if err := rows.Scan(&id, &tool); err != nil {
			return nil, fmt.Errorf("store.DedupGuardEvents: scan duplicate: %w", err)
		}
		if report.FirstDuplicateID == 0 {
			report.FirstDuplicateID = id
		}
		ids[id] = struct{}{}
		report.ByTool[tool]++
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.DedupGuardEvents: duplicates: %w", err)
	}
	report.Duplicates = len(ids)
	return ids, nil
}

// guardAnchorBefore returns the chain link the row at id must follow: the
// stored chain_hash of the newest earlier row, else the prune checkpoint,
// else the genesis anchor "".
func guardAnchorBefore(ctx context.Context, tx *sql.Tx, id int64) (string, error) {
	var anchor string
	err := tx.QueryRowContext(ctx,
		`SELECT chain_hash FROM guard_events WHERE id < ? ORDER BY id DESC LIMIT 1`, id).Scan(&anchor)
	switch {
	case err == nil:
		return anchor, nil
	case !errors.Is(err, sql.ErrNoRows):
		return "", fmt.Errorf("store.DedupGuardEvents: anchor: %w", err)
	}
	err = tx.QueryRowContext(ctx,
		`SELECT value FROM schema_meta WHERE key = ?`, guardChainCheckpointKey).Scan(&anchor)
	switch {
	case err == nil:
		return anchor, nil
	case errors.Is(err, sql.ErrNoRows):
		return "", nil
	default:
		return "", fmt.Errorf("store.DedupGuardEvents: checkpoint: %w", err)
	}
}

// loadGuardEventRowsTx loads every guard_events row with id >= fromID, in
// chain order, inside tx.
func loadGuardEventRowsTx(ctx context.Context, tx *sql.Tx, fromID int64) ([]GuardEventRow, error) {
	rows, err := tx.QueryContext(ctx,
		guardEventSelectColumns+` WHERE id >= ? ORDER BY id ASC`, fromID)
	if err != nil {
		return nil, fmt.Errorf("store.DedupGuardEvents: load: %w", err)
	}
	return loadGuardEventRows(rows, "store.DedupGuardEvents")
}

// firstSuffixBreak walks rows (chain order) from anchor and returns the id
// of the first row whose link or recomputed hash does not verify, with the
// failure class; 0 when the whole range verifies.
func firstSuffixBreak(anchor string, rows []GuardEventRow) (int64, string) {
	prev := anchor
	for i := range rows {
		r := &rows[i]
		if class := guardRowBreak(prev, r); class != "" {
			return r.ID, class
		}
		prev = r.ChainHash
	}
	return 0, ""
}
