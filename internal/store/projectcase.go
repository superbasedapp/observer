package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/platform/pathnorm"
)

// Windows project-root case (WINNODE2 item 11). Windows paths are
// case-insensitive, yet the projects table is keyed on the root_path text:
// a session whose cwd arrived as `c:\Users\dev\x` (VS Code's spelling) and
// one whose cwd arrived as `C:\Users\dev\x` (git's) were two projects, and
// two projects on the org. Ingest now upper-cases the drive letter
// (canonicalProjectRoot) and looks a Windows-shaped root up case-blind
// (projectRootFolded); MergeCaseDuplicateProjects folds the rows an older
// build already wrote.

// projectRootFolded returns the stored spelling of the oldest projects row
// whose root equals root ignoring ASCII case. The exact spelling is tried
// first through the unique index; the case-blind scan runs only when it
// misses.
func (s *Store) projectRootFolded(ctx context.Context, root string) (string, bool, error) {
	var stored string
	err := s.db.QueryRowContext(ctx, `SELECT root_path FROM projects WHERE root_path = ?`, root).Scan(&stored)
	if err == nil {
		return stored, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", false, fmt.Errorf("store.UpsertProject: exact root: %w", err)
	}
	err = s.db.QueryRowContext(ctx,
		`SELECT root_path FROM projects WHERE root_path = ? COLLATE NOCASE ORDER BY id LIMIT 1`, root).Scan(&stored)
	switch {
	case err == nil:
		return stored, true, nil
	case errors.Is(err, sql.ErrNoRows):
		return "", false, nil
	default:
		return "", false, fmt.Errorf("store.UpsertProject: case-blind root: %w", err)
	}
}

// planCaseDuplicateProjects groups Windows-shaped roots that differ only in
// case; in each group of two or more the oldest row (lowest id) survives
// and every other row merges into it. Pure and deterministic.
func planCaseDuplicateProjects(rows []ForeignProjectRootRow) []ProjectRootRepair {
	sorted := append([]ForeignProjectRootRow(nil), rows...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	survivor := map[string]ForeignProjectRootRow{}
	var out []ProjectRootRepair
	for _, r := range sorted {
		if !pathnorm.IsWindowsShaped(r.Root) {
			continue
		}
		key := strings.ToLower(r.Root)
		keep, ok := survivor[key]
		if !ok {
			survivor[key] = r
			continue
		}
		out = append(out, ProjectRootRepair{
			ProjectID: r.ID, Root: r.Root, NewRoot: keep.Root, Action: RepairMerge, TwinID: keep.ID,
		})
	}
	return out
}

// MergeCaseDuplicateProjects folds every Windows project row that differs
// from an older row only in case into that older row, in one transaction:
// sessions, actions and every other table holding a project id move to the
// survivor (mergeProjectRow, the root-repair merge; a row the survivor
// already holds under the same unique key is dropped, the survivor's copy
// wins), then the duplicate row is deleted. The survivor keeps its
// spelling and hash. Idempotent: a second run finds nothing to do. Returns
// the merges it made (empty when there was nothing to fold).
func (s *Store) MergeCaseDuplicateProjects(ctx context.Context) ([]ProjectRootRepair, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("store.MergeCaseDuplicateProjects: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := loadProjectRootRows(ctx, tx)
	if err != nil {
		return nil, err
	}
	merges := planCaseDuplicateProjects(rows)
	if len(merges) == 0 {
		return nil, nil
	}
	refCols, err := projectRefColumns(ctx, tx)
	if err != nil {
		return nil, err
	}
	existing, err := existingTables(ctx, tx)
	if err != nil {
		return nil, err
	}
	for i := range merges {
		if err := countRootKeyed(ctx, tx, &merges[i], existing); err != nil {
			return nil, err
		}
		if err := mergeProjectRow(ctx, tx, &merges[i], refCols); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store.MergeCaseDuplicateProjects: commit: %w", err)
	}
	return merges, nil
}
