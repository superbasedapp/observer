package db

import (
	"context"
	"database/sql"
	"reflect"
	"strconv"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db/migrations"
	"github.com/marmutapp/superbased-observer/internal/migplan"
	"github.com/marmutapp/superbased-observer/internal/migplan/sqliteledger/ledgertest"
)

// subjectStep is the sandbox installation lifecycle's late step (PT-89).
const subjectStep = 222

// subjectStepFile is its file (dropped to stage a build from before it).
const subjectStepFile = "222_tool_installs_subject.sql"

// TestToolInstallsSubjectLateStep stages the node databases a build with
// migration 222 meets and holds the runner to the plan each needs:
//
//   - pre-ledger, recorded at the head without 222 (a build of 230 to 248
//     whose ledger is gone): 222 runs, the old row reads subject_kind tool;
//   - the same shape with its ledger: 222 runs as an ordinary missing step;
//   - pre-ledger, already holding the 222 columns: 222 is adopted, never
//     re-run (its ALTERs would fail on the existing columns);
//   - fresh: 222 runs.
//
// After each, the columns and index exist, and a second start plans nothing.
func TestToolInstallsSubjectLateStep(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	head := LatestSchemaVersion()
	if head <= subjectStep {
		t.Fatalf("head %d is not above the late step %d", head, subjectStep)
	}
	oldLate := lateSteps[:len(lateSteps)-1]
	if oldLate[len(oldLate)-1].Version == subjectStep || lateSteps[len(lateSteps)-1].Version != subjectStep {
		t.Fatalf("lateSteps does not end with the %d row: %+v", subjectStep, lateSteps)
	}
	for _, tc := range []struct {
		name      string
		stage     func(t *testing.T, d *sql.DB)
		wantRun   []int
		wantState string
	}{
		{
			name: "pre-ledger at the head without 222",
			stage: func(t *testing.T, d *sql.DB) {
				if err := nodeRunner(ctx, d, lineageWithout(t, subjectStepFile), oldLate); err != nil {
					t.Fatalf("old build: %v", err)
				}
				seedToolInstall(ctx, t, d, false)
				ledgertest.StripLedger(t, d)
			},
			wantRun:   []int{subjectStep},
			wantState: migplan.RecordApplied,
		},
		{
			name: "ledger at the head without 222",
			stage: func(t *testing.T, d *sql.DB) {
				if err := nodeRunner(ctx, d, lineageWithout(t, subjectStepFile), oldLate); err != nil {
					t.Fatalf("old build: %v", err)
				}
				seedToolInstall(ctx, t, d, false)
			},
			wantRun:   []int{subjectStep},
			wantState: migplan.RecordApplied,
		},
		{
			name: "pre-ledger already holding 222",
			stage: func(t *testing.T, d *sql.DB) {
				if err := nodeRunner(ctx, d, migrations.Files, lateSteps); err != nil {
					t.Fatalf("current build: %v", err)
				}
				seedToolInstall(ctx, t, d, true)
				ledgertest.StripLedger(t, d)
			},
			wantRun:   nil,
			wantState: migplan.RecordAdopted,
		},
		{
			name:      "fresh",
			stage:     func(*testing.T, *sql.DB) {},
			wantState: migplan.RecordApplied,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d := ledgertest.OpenRaw(t)
			tc.stage(t, d)
			if tc.name != "fresh" {
				if got := planFrom(ctx, t, d, migrations.Files, lateSteps).RunVersions(); !reflect.DeepEqual(got, tc.wantRun) {
					t.Fatalf("plan runs %v, want %v", got, tc.wantRun)
				}
			}
			if err := nodeRunner(ctx, d, migrations.Files, lateSteps); err != nil {
				t.Fatalf("run: %v", err)
			}
			meta := ledgertest.Meta(t, d)
			if meta["version"] != strconv.Itoa(head) {
				t.Errorf("version = %q, want %d", meta["version"], head)
			}
			if got := meta[migplan.StepKey(subjectStep)]; got != tc.wantState {
				t.Errorf("migration:%d = %q, want %q", subjectStep, got, tc.wantState)
			}
			for _, col := range []string{"subject_kind", "backend", "source", "digest", "placed_path", "elevated"} {
				if !hasColumn(ctx, t, d, "tool_installs", col) {
					t.Errorf("tool_installs.%s missing", col)
				}
			}
			if !indexExists(t, d, "idx_tool_installs_subject") {
				t.Error("idx_tool_installs_subject missing")
			}
			if tc.name != "fresh" {
				checkSeededToolInstall(ctx, t, d)
			}
			if plan := planFrom(ctx, t, d, migrations.Files, lateSteps); !plan.Noop() {
				t.Fatalf("second start plans %+v, want nothing", plan)
			}
		})
	}
}

// seedToolInstall writes one AI-tool install record (and, once the columns
// exist, one sandbox record) that the run must keep.
func seedToolInstall(ctx context.Context, t *testing.T, d *sql.DB, withSubject bool) {
	t.Helper()
	mustExecDB(ctx, t, d, `INSERT INTO tool_installs (tool, channel, argv_json, display, status, started_at)
		VALUES ('codex', 'npm', '["npm","install","-g","@openai/codex"]', 'npm install -g @openai/codex', 'installed', '2026-11-06T00:00:00Z')`)
	if withSubject {
		mustExecDB(ctx, t, d, `INSERT INTO tool_installs (tool, channel, argv_json, display, status, started_at, subject_kind, backend, elevated)
			VALUES ('bwrap', 'apt', '["sudo","apt-get","install","-y","bubblewrap"]', 'sudo apt-get install -y bubblewrap', 'installed', '2026-11-06T00:00:00Z', 'sandbox', 'bwrap', 1)`)
	}
}

// checkSeededToolInstall reads back what seedToolInstall wrote: the tool row
// reads subject_kind tool.
func checkSeededToolInstall(ctx context.Context, t *testing.T, d *sql.DB) {
	t.Helper()
	var subject, backend string
	if err := d.QueryRowContext(ctx, `SELECT subject_kind, backend FROM tool_installs WHERE tool = 'codex'`).Scan(&subject, &backend); err != nil || subject != "tool" || backend != "" {
		t.Errorf("codex row = (%q, %q, %v), want (tool, \"\")", subject, backend, err)
	}
}
