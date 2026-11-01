package compaction

import (
	"context"
	"database/sql"
	"fmt"
)

// MoveProjectEvents moves project fromID's compaction_events rows onto
// project toID inside tx (`observer backfill --worktree-roots`, lane
// shr-worktree2, PT-39). The table has no project-scoped unique key, so
// every row moves. toID 0 counts what would move, changing nothing.
func MoveProjectEvents(ctx context.Context, tx *sql.Tx, fromID, toID int64) (int64, error) {
	if toID == 0 {
		var n int64
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM compaction_events WHERE project_id = ?`, fromID).Scan(&n); err != nil {
			return 0, fmt.Errorf("compaction.MoveProjectEvents: count: %w", err)
		}
		return n, nil
	}
	res, err := tx.ExecContext(ctx, `UPDATE compaction_events SET project_id = ? WHERE project_id = ?`, toID, fromID)
	if err != nil {
		return 0, fmt.Errorf("compaction.MoveProjectEvents: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
