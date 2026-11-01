package store

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/platform/pathnorm"
)

// Project-root repair: the one-shot fix for projects rows written before
// canonicalProjectRoot ran on every ingest path. A Windows tool's raw cwd
// (Claude Code's wsl.exe hook bridge, kimchi, autohand, codex hooks) and a
// URI that never got decoded (antigravity-cli's `file://C:\...`, which
// filepath.Abs then joined onto the daemon's cwd) each produced a second
// row for a directory an adapter had already stored translated. Those rows
// split one project's history and feed guard rule R-151 roots in a flavor
// the rest of the node never uses.
//
// The plan is pure (planProjectRootRepairs); RepairProjectRoots executes it
// in one transaction and commits it only when asked to.

// ProjectRootRepairAction is what the repair does with one bad row.
type ProjectRootRepairAction string

const (
	// RepairRename rewrites the row's root_path in place: no row holds the
	// canonical spelling yet, so every reference stays valid untouched.
	RepairRename ProjectRootRepairAction = "rename"
	// RepairMerge re-points every reference to the row that already holds
	// the canonical spelling (the twin) and deletes the bad row.
	RepairMerge ProjectRootRepairAction = "merge"
)

// ProjectRootRepair is one planned (or applied) repair of a projects row.
type ProjectRootRepair struct {
	ProjectID int64                   `json:"project_id"`
	Root      string                  `json:"root"`
	NewRoot   string                  `json:"new_root"`
	Action    ProjectRootRepairAction `json:"action"`
	// TwinID is the row a merge re-points to (0 for a rename).
	TwinID int64 `json:"twin_id,omitempty"`
	// Repointed counts, per table.column, the rows that reference this
	// project id: the rows a merge moves to the twin.
	Repointed map[string]int64 `json:"repointed,omitempty"`
	// Collisions counts, per table.column, the rows a merge could not move
	// because the twin already holds a row with the same unique key (a
	// derived cache such as file_state or project_commits). They are
	// deleted; the twin's copy wins.
	Collisions map[string]int64 `json:"collisions,omitempty"`
	// RootKeyed counts rows in tables that name a project by its root path
	// or root hash rather than its id (handoffs, codeintel, guard approvals,
	// ...). They are reported, never rewritten: they are history keyed by
	// the spelling they were written under.
	RootKeyed map[string]int64 `json:"root_keyed,omitempty"`
}

// ProjectRootRepairReport is the result of RepairProjectRoots.
type ProjectRootRepairReport struct {
	Applied bool                `json:"applied"`
	Repairs []ProjectRootRepair `json:"repairs"`
	// Unrepaired lists foreign-looking roots that have no unambiguous host
	// spelling (a drive-relative `C:Users\...`, a generic UNC share). They
	// are left alone.
	Unrepaired []ForeignProjectRootRow `json:"unrepaired,omitempty"`
}

// ForeignProjectRootRow is one projects row as the foreign-root repair
// planner sees it (distinct from ProjectRootRow, the worktree-roots scan row).
type ForeignProjectRootRow struct {
	ID   int64  `json:"id"`
	Root string `json:"root"`
}

// rootRepairRules is the ordered rule table repairedProjectRoot walks: the
// first rule whose extract matches yields the candidate spelling, which is
// then canonicalized like any ingest root.
var rootRepairRules = []struct {
	name    string
	extract func(root string) (string, bool)
}{
	{
		// `/home/<user>/file:/C:\x`: a file URI that reached filepath.Abs
		// undecoded and was joined onto the daemon's cwd. The URI starts at
		// the "file:" segment; what precedes it is the cwd, not the root.
		name: "embedded file URI",
		extract: func(root string) (string, bool) {
			i := strings.Index(strings.ToLower(root), "/file:/")
			if i < 0 {
				return "", false
			}
			return root[i+1:], true
		},
	},
	{
		name:    "foreign or URI spelling",
		extract: func(root string) (string, bool) { return root, true },
	},
}

// repairedProjectRoot returns the canonical spelling a stored root should
// have had, and whether it differs from root.
func repairedProjectRoot(root string) (string, bool) {
	for _, rule := range rootRepairRules {
		cand, ok := rule.extract(root)
		if !ok {
			continue
		}
		next := canonicalProjectRoot(cand)
		if next == "" || next == root {
			return root, false
		}
		if pathnorm.IsWindowsShaped(root) && strings.EqualFold(next, root) {
			// A case-only difference (a lower-case drive letter) is not a
			// foreign spelling: renaming would change the project's hash
			// on the org wire. MergeCaseDuplicateProjects folds such rows.
			return root, false
		}
		return next, true
	}
	return root, false
}

// looksForeignRoot reports whether a root that the repair leaves alone
// still carries a Windows or URI spelling, so the report can name it.
func looksForeignRoot(root string) bool {
	if strings.HasPrefix(root, "[") {
		return false // synthetic roots such as "[antigravity]"
	}
	if len(root) >= 2 && root[1] == ':' {
		return true
	}
	return strings.Contains(root, `\`) || strings.Contains(strings.ToLower(root), "file:")
}

// planProjectRootRepairs decides every row: a row whose canonical spelling
// differs is renamed when no row holds that spelling, or merged into the
// row that does. Several bad rows sharing one canonical spelling with no
// existing twin rename the lowest id and merge the rest into it. Rows are
// processed in id order, so the plan is deterministic.
func planProjectRootRepairs(rows []ForeignProjectRootRow) (repairs []ProjectRootRepair, unrepaired []ForeignProjectRootRow) {
	sorted := append([]ForeignProjectRootRow(nil), rows...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })

	byRoot := make(map[string]int64, len(sorted))
	for _, r := range sorted {
		byRoot[r.Root] = r.ID
	}
	// Canonical spellings already claimed by a planned rename, so later
	// bad rows with the same spelling merge into the renamed row.
	claimed := map[string]int64{}
	for _, r := range sorted {
		next, changed := repairedProjectRoot(r.Root)
		if !changed {
			if looksForeignRoot(r.Root) {
				unrepaired = append(unrepaired, r)
			}
			continue
		}
		rep := ProjectRootRepair{ProjectID: r.ID, Root: r.Root, NewRoot: next}
		if twin, ok := byRoot[next]; ok {
			rep.Action, rep.TwinID = RepairMerge, twin
		} else if twin, ok := claimed[next]; ok {
			rep.Action, rep.TwinID = RepairMerge, twin
		} else {
			rep.Action = RepairRename
			claimed[next] = r.ID
		}
		repairs = append(repairs, rep)
	}
	return repairs, unrepaired
}

// projectRefKeep are tables with a project id column the merge must NOT
// re-point, each with the reason. Their rows keep the bad id (none of them
// has a foreign key, so the delete of the bad row still succeeds).
var projectRefKeep = map[string]string{
	// A tombstone names the project its row was deleted under; the org
	// matches it against what was pushed then.
	"org_push_deletions": "tombstones keep the project they were deleted under",
}

// projectRefColumns lists every (table, column) that references
// projects.id, discovered from the schema so a later migration's table is
// covered without editing this file. A column counts when it is named
// project_id or local_project_id, the two spellings the schema uses for a
// local project id. Tables in projectRefKeep are left out.
func projectRefColumns(ctx context.Context, q queryer) ([][2]string, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT m.name, c.name
		  FROM sqlite_master m
		  JOIN pragma_table_info(m.name) c
		 WHERE m.type = 'table' AND m.name <> 'projects'
		   AND c.name IN ('project_id', 'local_project_id')
		 ORDER BY m.name, c.name`)
	if err != nil {
		return nil, fmt.Errorf("store.projectRefColumns: %w", err)
	}
	defer rows.Close()
	var out [][2]string
	for rows.Next() {
		var t, c string
		if err := rows.Scan(&t, &c); err != nil {
			return nil, fmt.Errorf("store.projectRefColumns: scan: %w", err)
		}
		if _, keep := projectRefKeep[t]; keep {
			continue
		}
		out = append(out, [2]string{t, c})
	}
	return out, rows.Err()
}

// rootKeyedColumns are the tables that name a project by root path or root
// hash (the plain sha256 hex of the root, secposture.ProjectRootHash's
// recipe). The repair and the Windows case fold only count them (see
// ProjectRootRepair.RootKeyed); the case fold logs the counts at daemon
// start. Rewriting them is a follow-up (WINNODE2 merge, audit M1). A table
// missing from the schema is skipped.
var rootKeyedColumns = []struct {
	table, column string
	hashed        bool
}{
	{"handoffs", "project_root", false},
	{"arena_runs", "project_root", false},
	{"project_guidance_files", "project_root", false},
	{"session_skill_snapshots", "project_root", false},
	{"agent_config_layers", "project_root", false},
	// The organization's AI tool settings state (migration 157).
	{"agent_config_org_state", "project_root", false},
	// The codeintel index and graph (migrations 050 to 052, 092).
	{"codeintel_files", "project", false},
	{"codeintel_nodes", "project", false},
	{"codeintel_edges", "project", false},
	{"codeintel_sites", "project", false},
	{"codeintel_embeddings", "project", false},
	{"codeintel_minhash", "project", false},
	{"codeintel_archived_projects", "project", false},
	{"guard_approvals", "project_root_hash", true},
	{"terminal_run", "project_root_hash", true},
	{"org_access_grants", "project_root_hash", true},
}

// allRootKeyedColumns is rootKeyedColumns plus the security pillar's
// tables, which only the read-only projectrootrepair_sec.go may name
// (TestSecTablesHaveOneWriter).
var allRootKeyedColumns = append(append(rootKeyedColumns[:0:0], rootKeyedColumns...), secRootKeyedColumns...)

// queryer is the read half shared by *sql.DB and *sql.Tx.
type queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// RepairProjectRoots plans the repair of every projects row stored under a
// foreign or undecoded spelling and executes it in one transaction: renames
// rewrite root_path (and its hash) in place; merges re-point every
// project-id reference to the twin, delete the rows the twin already holds
// under the same unique key, and delete the bad row. The transaction is
// committed only when apply is true; a dry run executes the same
// statements and rolls back, so its counts (collisions included) are exact.
// Root-keyed tables are counted, never rewritten.
//
// Run it only on a daemon that already canonicalizes at ingest; an older
// build would recreate the rows on its next hook batch. The guard's R-151
// root set is a daemon-start snapshot, so restart the daemon afterwards.
func (s *Store) RepairProjectRoots(ctx context.Context, apply bool) (ProjectRootRepairReport, error) {
	report := ProjectRootRepairReport{Applied: apply}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return report, fmt.Errorf("store.RepairProjectRoots: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := loadProjectRootRows(ctx, tx)
	if err != nil {
		return report, err
	}
	repairs, unrepaired := planProjectRootRepairs(rows)
	report.Unrepaired = unrepaired
	refCols, err := projectRefColumns(ctx, tx)
	if err != nil {
		return report, err
	}
	existing, err := existingTables(ctx, tx)
	if err != nil {
		return report, err
	}

	for i := range repairs {
		rep := &repairs[i]
		if err := countRootKeyed(ctx, tx, rep, existing); err != nil {
			return report, err
		}
		if rep.Action == RepairRename {
			if _, err := tx.ExecContext(ctx,
				`UPDATE projects SET root_path = ?, root_path_hash = ? WHERE id = ?`,
				rep.NewRoot, sha256Hex(rep.NewRoot), rep.ProjectID); err != nil {
				return report, fmt.Errorf("store.RepairProjectRoots: rename %d: %w", rep.ProjectID, err)
			}
			continue
		}
		if err := mergeProjectRow(ctx, tx, rep, refCols); err != nil {
			return report, err
		}
	}
	report.Repairs = repairs
	if !apply {
		return report, nil
	}
	if err := tx.Commit(); err != nil {
		return report, fmt.Errorf("store.RepairProjectRoots: commit: %w", err)
	}
	return report, nil
}

// mergeProjectRow moves every reference to rep.ProjectID onto rep.TwinID
// and deletes the bad row.
func mergeProjectRow(ctx context.Context, tx *sql.Tx, rep *ProjectRootRepair, refCols [][2]string) error {
	for _, tc := range refCols {
		key := tc[0] + "." + tc[1]
		var n int64
		if err := tx.QueryRowContext(ctx,
			fmt.Sprintf(`SELECT COUNT(*) FROM %q WHERE %q = ?`, tc[0], tc[1]), rep.ProjectID).Scan(&n); err != nil {
			return fmt.Errorf("store.RepairProjectRoots: count %s: %w", key, err)
		}
		if n == 0 {
			continue
		}
		res, err := tx.ExecContext(ctx,
			fmt.Sprintf(`UPDATE OR IGNORE %q SET %q = ? WHERE %q = ?`, tc[0], tc[1], tc[1]), rep.TwinID, rep.ProjectID)
		if err != nil {
			return fmt.Errorf("store.RepairProjectRoots: repoint %s: %w", key, err)
		}
		moved, _ := res.RowsAffected()
		if moved > 0 {
			addCount(&rep.Repointed, key, moved)
		}
		if moved == n {
			continue
		}
		res, err = tx.ExecContext(ctx,
			fmt.Sprintf(`DELETE FROM %q WHERE %q = ?`, tc[0], tc[1]), rep.ProjectID)
		if err != nil {
			return fmt.Errorf("store.RepairProjectRoots: drop collisions %s: %w", key, err)
		}
		dropped, _ := res.RowsAffected()
		addCount(&rep.Collisions, key, dropped)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM projects WHERE id = ?`, rep.ProjectID); err != nil {
		return fmt.Errorf("store.RepairProjectRoots: delete %d: %w", rep.ProjectID, err)
	}
	return nil
}

// countRootKeyed fills rep.RootKeyed for the tables present in this schema.
func countRootKeyed(ctx context.Context, tx *sql.Tx, rep *ProjectRootRepair, existing map[string]bool) error {
	for _, rk := range allRootKeyedColumns {
		if !existing[rk.table] {
			continue
		}
		val := rep.Root
		if rk.hashed {
			val = sha256Hex(rep.Root)
		}
		var n int64
		if err := tx.QueryRowContext(ctx,
			fmt.Sprintf(`SELECT COUNT(*) FROM %q WHERE %q = ?`, rk.table, rk.column), val).Scan(&n); err != nil {
			return fmt.Errorf("store.RepairProjectRoots: count %s.%s: %w", rk.table, rk.column, err)
		}
		if n > 0 {
			addCount(&rep.RootKeyed, rk.table+"."+rk.column, n)
		}
	}
	return nil
}

func addCount(m *map[string]int64, key string, n int64) {
	if *m == nil {
		*m = map[string]int64{}
	}
	(*m)[key] += n
}

func loadProjectRootRows(ctx context.Context, q queryer) ([]ForeignProjectRootRow, error) {
	rows, err := q.QueryContext(ctx, `SELECT id, root_path FROM projects ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("store.RepairProjectRoots: load: %w", err)
	}
	defer rows.Close()
	var out []ForeignProjectRootRow
	for rows.Next() {
		var r ForeignProjectRootRow
		if err := rows.Scan(&r.ID, &r.Root); err != nil {
			return nil, fmt.Errorf("store.RepairProjectRoots: scan: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func existingTables(ctx context.Context, q queryer) (map[string]bool, error) {
	rows, err := q.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table'`)
	if err != nil {
		return nil, fmt.Errorf("store.RepairProjectRoots: tables: %w", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, fmt.Errorf("store.RepairProjectRoots: tables scan: %w", err)
		}
		out[n] = true
	}
	return out, rows.Err()
}
