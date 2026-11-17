package db

import (
	"context"
	"database/sql"
	"io/fs"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/marmutapp/superbased-observer/internal/db/migrations"
	"github.com/marmutapp/superbased-observer/internal/migplan"
	"github.com/marmutapp/superbased-observer/internal/migplan/sqliteledger/ledgertest"
)

// The main merge (2026-11-06, plans decision log P-247) retired node 213, 214
// and 216 and renumbered the steps that held them. These are the old names,
// mapped to the files that now carry the same SQL (only header comments
// changed).
var (
	// mainOldSteps is what a build of main at 9101e81f2 embedded above the
	// shared 211: 212 and 215 keep their numbers.
	mainOldSteps = map[string]string{
		"212_process_capture_budget.sql":        "212_process_capture_budget.sql",
		"213_process_runs_service_root_idx.sql": "217_process_runs_service_root_idx.sql",
		"214_project_quality_daily.sql":         "219_project_quality_daily.sql",
		"215_codeintel_complexity.sql":          "215_codeintel_complexity.sql",
		"216_project_quality_complexity.sql":    "221_project_quality_complexity.sql",
	}
	// releaseOldSteps is what a build of the release line at 93f69b8f6
	// embedded above the shared 211 and below its 230 to 248.
	releaseOldSteps = map[string]string{
		"213_guard_approvals_unique.sql": "218_guard_approvals_unique.sql",
		"214_terminal_run_initiator.sql": "220_terminal_run_initiator.sql",
	}
)

// releaseLineHead is the release line's node head at 93f69b8f6: its 230 to
// 248. A step authored after the merge (249 on) was never in that build.
const releaseLineHead = 248

// oldLineage is the shared lineage through 211, the old-numbered steps, and
// every current step from from up to releaseLineHead (from 0 for none).
func oldLineage(t *testing.T, old map[string]string, from int) fstest.MapFS {
	t.Helper()
	out := lineageThrough(t, 211)
	for name, cur := range old {
		b, err := fs.ReadFile(migrations.Files, cur)
		if err != nil {
			t.Fatalf("read %s: %v", cur, err)
		}
		out[name] = &fstest.MapFile{Data: b}
	}
	if from > 0 {
		des, err := fs.ReadDir(migrations.Files, ".")
		if err != nil {
			t.Fatal(err)
		}
		for _, de := range des {
			v, err := strconv.Atoi(strings.SplitN(de.Name(), "_", 2)[0])
			if err != nil || v < from || v > releaseLineHead || !strings.HasSuffix(de.Name(), ".sql") {
				continue
			}
			b, err := fs.ReadFile(migrations.Files, de.Name())
			if err != nil {
				t.Fatal(err)
			}
			out[de.Name()] = &fstest.MapFile{Data: b}
		}
	}
	return out
}

// TestMergeMainLedgerShapes stages the three node databases the merged build
// meets after P-247 and runs the merged lineage on each:
//
//   - main shape: main's 212 to 216 applied (version 216), the build the
//     operator's own node ran;
//   - release-line shape: the release line's 213 and 214 and 230 to 248
//     applied (version 248);
//   - fresh.
//
// On each, every embedded step ends applied or adopted, the moved steps'
// objects exist, the orphan records of the retired numbers stay and break
// nothing, and a second start plans nothing.
func TestMergeMainLedgerShapes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	head := LatestSchemaVersion()
	headStr := strconv.Itoa(head)
	entries, err := readMigrationEntries()
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name    string
		stage   func(t *testing.T) fs.FS // nil: fresh
		version int                      // staged version record
		applied []int                    // moved steps the merged run must run
		adopted []int                    // moved steps the merged run must adopt
		orphans []int                    // retired numbers recorded by the old build
	}{
		{
			name:    "main shape at 216",
			stage:   func(t *testing.T) fs.FS { return oldLineage(t, mainOldSteps, 0) },
			version: 216,
			applied: []int{217, 218, 219, 220},
			adopted: []int{221},
			orphans: []int{213, 214, 216},
		},
		{
			name:    "release line shape at 248",
			stage:   func(t *testing.T) fs.FS { return oldLineage(t, releaseOldSteps, 230) },
			version: 248,
			applied: []int{212, 215, 217, 218, 219, 221},
			adopted: []int{220},
			orphans: []int{213, 214},
		},
		{
			name:    "fresh",
			applied: []int{212, 215, 217, 218, 219, 220, 221},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d := ledgertest.OpenRaw(t)
			if tc.stage != nil {
				// The old builds carried only the wave fork's late steps.
				if err := nodeRunner(ctx, d, tc.stage(t), lateSteps[:2]); err != nil {
					t.Fatalf("old build: %v", err)
				}
				if v, _ := Version(ctx, d); v != tc.version {
					t.Fatalf("staged version = %d, want %d", v, tc.version)
				}
				// Seed a row the merged run must keep (main shape: the
				// quality trend with its complexity state; release shape: a
				// launch's initiator).
				seedMergeShape(ctx, t, d, tc.name)
			}
			if err := nodeRunner(ctx, d, migrations.Files, lateSteps); err != nil {
				t.Fatalf("merged build: %v", err)
			}
			meta := ledgertest.Meta(t, d)
			if meta["version"] != headStr {
				t.Fatalf("version = %q, want the head %d", meta["version"], head)
			}
			for _, e := range entries {
				if r := meta[migplan.StepKey(e.version)]; r != migplan.RecordApplied && r != migplan.RecordAdopted {
					t.Errorf("migration:%d = %q, want applied or adopted", e.version, r)
				}
			}
			for _, v := range tc.applied {
				if r := meta[migplan.StepKey(v)]; r != migplan.RecordApplied {
					t.Errorf("migration:%d = %q, want applied", v, r)
				}
			}
			for _, v := range tc.adopted {
				if r := meta[migplan.StepKey(v)]; r != migplan.RecordAdopted {
					t.Errorf("migration:%d = %q, want adopted", v, r)
				}
			}
			for _, v := range tc.orphans {
				if r := meta[migplan.StepKey(v)]; r != migplan.RecordApplied {
					t.Errorf("orphan migration:%d = %q, want the old build's applied record kept", v, r)
				}
			}
			for _, idx := range []string{"idx_guard_approvals_key", "idx_process_runs_session_service"} {
				if !indexExists(t, d, idx) {
					t.Errorf("index %s missing", idx)
				}
			}
			for _, c := range [][2]string{
				{"project_quality_daily", "complexity_state"},
				{"project_quality_daily", "dup_state"},
				{"codeintel_nodes", "complexity"},
				{"codeintel_files", "extract_version"},
				{"terminal_run", "initiator"},
				{"terminal_run", "parent_session_id"},
				{"process_runs", "capture_class"},
				{"process_rollups", "group_kind"},
			} {
				if !hasColumn(ctx, t, d, c[0], c[1]) {
					t.Errorf("%s.%s missing", c[0], c[1])
				}
			}
			checkMergeShapeSeed(ctx, t, d, tc.name)
			if plan := planFrom(ctx, t, d, migrations.Files, lateSteps); !plan.Noop() {
				t.Fatalf("second start plans %+v, want nothing", plan)
			}
		})
	}
}

// seedMergeShape writes the row each old shape must carry through the merged
// run.
func seedMergeShape(ctx context.Context, t *testing.T, d *sql.DB, shape string) {
	t.Helper()
	switch {
	case strings.HasPrefix(shape, "main"):
		mustExecDB(ctx, t, d, `INSERT INTO projects (id, root_path, created_at) VALUES (1, '/p', '2026-11-05T00:00:00Z')`)
		mustExecDB(ctx, t, d, `INSERT INTO project_quality_daily (project_id, day, measured_at, complexity_state, complexity_functions)
			VALUES (1, '2026-11-05', '2026-11-05T00:00:00Z', 'measured', 7)`)
	case strings.HasPrefix(shape, "release"):
		mustExecDB(ctx, t, d, `INSERT INTO guard_approvals (ts, rule_id, scope, session_id, project_root_hash, granted_by, expires_at)
			VALUES ('2026-11-05T00:00:00Z', 'S-794', 'global', '', '', 'dashboard', '')`)
	}
}

// checkMergeShapeSeed reads back what seedMergeShape wrote.
func checkMergeShapeSeed(ctx context.Context, t *testing.T, d *sql.DB, shape string) {
	t.Helper()
	switch {
	case strings.HasPrefix(shape, "main"):
		var st string
		var n int
		if err := d.QueryRowContext(ctx, `SELECT complexity_state, complexity_functions FROM project_quality_daily WHERE project_id = 1`).Scan(&st, &n); err != nil || st != "measured" || n != 7 {
			t.Errorf("quality row = (%q, %d, %v), want (measured, 7) kept", st, n, err)
		}
	case strings.HasPrefix(shape, "release"):
		var n int
		if err := d.QueryRowContext(ctx, `SELECT COUNT(*) FROM guard_approvals WHERE rule_id = 'S-794'`).Scan(&n); err != nil || n != 1 {
			t.Errorf("guard_approvals S-794 rows = %d (%v), want 1 kept", n, err)
		}
	}
}

func mustExecDB(ctx context.Context, t *testing.T, d *sql.DB, q string) {
	t.Helper()
	if _, err := d.ExecContext(ctx, q); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}
