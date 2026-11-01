package freshness

import (
	"context"
	"database/sql"
	"fmt"
)

// fileStateSwapMark suffixes a file_path while a clashing row steps aside
// during MoveProjectFileState; no real path ends with it.
const fileStateSwapMark = "\n#shr-worktree2-swap"

// FileStateMove counts what MoveProjectFileState moved.
type FileStateMove struct {
	// Moved is how many rows now sit on the target project.
	Moved int64
	// KeptOnOld is how many rows stayed on the old project: for each
	// file_path both projects hold, the older of the two rows.
	KeptOnOld int64
	// Swapped is how many of those clashes the old project's row won (it
	// was newer), so the target's older row went to the old project.
	Swapped int64
}

// MoveProjectFileState moves project fromID's file_state rows onto project
// toID inside tx (`observer backfill --worktree-roots`, lane
// shr-worktree2, PT-39). file_state is unique on (project_id, file_path);
// when both projects hold a row for one path, the newer row (by
// last_seen_at) ends on toID and the older one stays on fromID: nothing is
// deleted or overwritten. toID 0 counts what would move to a project that
// has no rows yet, changing nothing.
func MoveProjectFileState(ctx context.Context, tx *sql.Tx, fromID, toID int64) (FileStateMove, error) {
	var m FileStateMove
	if toID == 0 {
		err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM file_state WHERE project_id = ?`, fromID).Scan(&m.Moved)
		if err != nil {
			return m, fmt.Errorf("freshness.MoveProjectFileState: count: %w", err)
		}
		return m, nil
	}
	var marked int64
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM file_state WHERE project_id IN (?, ?) AND substr(file_path, -length(?)) = ?`,
		fromID, toID, fileStateSwapMark, fileStateSwapMark).Scan(&marked); err != nil {
		return m, fmt.Errorf("freshness.MoveProjectFileState: %w", err)
	}
	if marked > 0 {
		return m, fmt.Errorf("freshness.MoveProjectFileState: %d file_state row(s) already carry the swap mark", marked)
	}
	// 1. The target's rows that are older than the old project's row for
	// the same path step aside onto the old project under a marked path.
	res, err := tx.ExecContext(ctx, `
		UPDATE file_state SET project_id = ?, file_path = file_path || ?
		 WHERE project_id = ? AND EXISTS (
		   SELECT 1 FROM file_state s
		    WHERE s.project_id = ? AND s.file_path = file_state.file_path
		      AND julianday(s.last_seen_at) > julianday(file_state.last_seen_at))`,
		fromID, fileStateSwapMark, toID, fromID)
	if err != nil {
		return m, fmt.Errorf("freshness.MoveProjectFileState: step aside: %w", err)
	}
	m.Swapped, _ = res.RowsAffected()
	// 2. Every old row the target no longer holds a path for moves.
	res, err = tx.ExecContext(ctx, `
		UPDATE file_state SET project_id = ?
		 WHERE project_id = ? AND substr(file_path, -length(?)) != ?
		   AND NOT EXISTS (SELECT 1 FROM file_state t WHERE t.project_id = ? AND t.file_path = file_state.file_path)`,
		toID, fromID, fileStateSwapMark, fileStateSwapMark, toID)
	if err != nil {
		return m, fmt.Errorf("freshness.MoveProjectFileState: move: %w", err)
	}
	m.Moved, _ = res.RowsAffected()
	// 3. The rows that stepped aside take their real path back.
	if _, err := tx.ExecContext(ctx, `
		UPDATE file_state SET file_path = substr(file_path, 1, length(file_path) - length(?))
		 WHERE project_id = ? AND substr(file_path, -length(?)) = ?`,
		fileStateSwapMark, fromID, fileStateSwapMark, fileStateSwapMark); err != nil {
		return m, fmt.Errorf("freshness.MoveProjectFileState: restore: %w", err)
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM file_state WHERE project_id = ?`, fromID).Scan(&m.KeptOnOld); err != nil {
		return m, fmt.Errorf("freshness.MoveProjectFileState: count kept: %w", err)
	}
	return m, nil
}
