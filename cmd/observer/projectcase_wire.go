package main

import (
	"context"
	"database/sql"
	"log/slog"

	"github.com/marmutapp/superbased-observer/internal/store"
)

// mergeCaseDuplicateProjectsAtStart folds, once per daemon start and before
// the watcher's first scan, the Windows project rows an older build split
// by case (`C:\x` and `c:\x`, WINNODE2 item 11). It is idempotent: a node
// with nothing to fold does one read of the projects table and logs
// nothing. A failure is logged and changes nothing (one transaction). Each
// fold also logs, per table, the rows that name the folded project by its
// old spelling or that spelling's hash (guard approvals, access grants,
// security records, codeintel, ...): they are left as they are, so one that
// stops matching after the fold can be traced (WINNODE2 merge, audit M1).
func mergeCaseDuplicateProjectsAtStart(ctx context.Context, database *sql.DB, logger *slog.Logger) {
	merges, err := store.New(database).MergeCaseDuplicateProjects(ctx)
	if err != nil {
		logger.Warn("projects: could not fold Windows project rows that differ only in case; they stay separate", "err", err)
		return
	}
	for _, m := range merges {
		var moved, dropped int64
		for _, n := range m.Repointed {
			moved += n
		}
		for _, n := range m.Collisions {
			dropped += n
		}
		logger.Info("projects: folded a Windows project row that differed only in case into the oldest row",
			"from_id", m.ProjectID, "from_root", m.Root, "into_id", m.TwinID, "into_root", m.NewRoot,
			"rows_moved", moved, "rows_dropped_as_duplicates", dropped, "by_table", m.Repointed,
			"root_keyed_left_on_old_spelling", m.RootKeyed)
	}
}
