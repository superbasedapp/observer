package db

import (
	"context"
	"database/sql"
	"io/fs"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/marmutapp/superbased-observer/internal/db/migrations"
	"github.com/marmutapp/superbased-observer/internal/migplan"
	"github.com/marmutapp/superbased-observer/internal/migplan/sqliteledger"
	"github.com/marmutapp/superbased-observer/internal/migplan/sqliteledger/ledgertest"
)

// guardAnchorFile is main's 177_guard_action_anchor.sql, renumbered to 197 at
// the plans merge (2026-10-25).
const guardAnchorFile = "197_guard_action_anchor.sql"

// lineageThrough copies the embedded node lineage up to and including step
// max: what a binary built at that head embedded. A plans-line binary stops
// at 196, so the staged plans-line database is built from lineageThrough(196).
func lineageThrough(t *testing.T, max int) fstest.MapFS {
	t.Helper()
	out := fstest.MapFS{}
	des, err := fs.ReadDir(migrations.Files, ".")
	if err != nil {
		t.Fatalf("read lineage: %v", err)
	}
	for _, de := range des {
		v, err := strconv.Atoi(strings.SplitN(de.Name(), "_", 2)[0])
		if de.IsDir() || !strings.HasSuffix(de.Name(), ".sql") || err != nil || v > max {
			continue
		}
		b, err := fs.ReadFile(migrations.Files, de.Name())
		if err != nil {
			t.Fatalf("read %s: %v", de.Name(), err)
		}
		out[de.Name()] = &fstest.MapFile{Data: b}
	}
	return out
}

// waveLineage is the node lineage a wave build (main's
// wave-followups-2026-10-24 line) embedded: the shared 001-176 plus
// guard_action_anchor under its original number 177. The wave's 077 differs
// from the shipped 077 only by extra action_type UPDATEs for its ten adapters,
// which no later step depends on, so the shipped bytes stand in for it.
func waveLineage(t *testing.T) fstest.MapFS {
	t.Helper()
	out := fstest.MapFS{}
	des, err := fs.ReadDir(migrations.Files, ".")
	if err != nil {
		t.Fatalf("read lineage: %v", err)
	}
	for _, de := range des {
		if de.IsDir() || !strings.HasSuffix(de.Name(), ".sql") {
			continue
		}
		v, err := strconv.Atoi(strings.SplitN(de.Name(), "_", 2)[0])
		if err != nil {
			t.Fatalf("lineage name %q: %v", de.Name(), err)
		}
		if v > 176 {
			continue
		}
		b, err := fs.ReadFile(migrations.Files, de.Name())
		if err != nil {
			t.Fatalf("read %s: %v", de.Name(), err)
		}
		out[de.Name()] = &fstest.MapFile{Data: b}
	}
	b, err := fs.ReadFile(migrations.Files, guardAnchorFile)
	if err != nil {
		t.Fatalf("read %s: %v", guardAnchorFile, err)
	}
	out["177_guard_action_anchor.sql"] = &fstest.MapFile{Data: b}
	return out
}

// planFrom is the read-only plan the runner would execute over source.
func planFrom(ctx context.Context, t *testing.T, d *sql.DB, source fs.FS, late []migplan.LateStep) migplan.Plan {
	t.Helper()
	entries, err := readMigrationEntriesFrom(source)
	if err != nil {
		t.Fatalf("lineage: %v", err)
	}
	embedded, _ := lineageIndex(entries)
	plan, err := sqliteledger.Plan(ctx, d, embedded, late)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	return plan
}

// hasColumn reports whether table has column on d.
func hasColumn(ctx context.Context, t *testing.T, d *sql.DB, table, column string) bool {
	t.Helper()
	var n int
	if err := d.QueryRowContext(ctx, `SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?`, table, column).Scan(&n); err != nil {
		t.Fatalf("probe %s.%s: %v", table, column, err)
	}
	return n > 0
}

// TestNodeLateStepsTable pins the node late-step table to exactly its rows
// (see lateSteps): the wave lineage fork's two, the main merge's two
// (P-247) and the sandbox installation lifecycle's one (PT-89), and each
// probe to a column its own step creates. A new row
// belongs here only for a real interleaving, with a staged test like
// TestWaveLineageFork or TestMergeMainLedgerShapes.
func TestNodeLateStepsTable(t *testing.T) {
	want := []migplan.LateStep{
		{Version: 177, Table: "sec_findings", Column: "local_key"},
		{Version: 197, Table: "guard_events", Column: "action_anchor"},
		{Version: 220, Table: "terminal_run", Column: "initiator"},
		{Version: 221, Table: "project_quality_daily", Column: "complexity_state"},
		{Version: 222, Table: "tool_installs", Column: "subject_kind"},
	}
	if !reflect.DeepEqual(lateSteps, want) {
		t.Fatalf("lateSteps = %+v, want %+v", lateSteps, want)
	}
	des, err := fs.ReadDir(migrations.Files, ".")
	if err != nil {
		t.Fatalf("read lineage: %v", err)
	}
	for _, s := range want {
		var body []byte
		for _, de := range des {
			if strings.HasPrefix(de.Name(), strconv.Itoa(s.Version)+"_") {
				if body, err = fs.ReadFile(migrations.Files, de.Name()); err != nil {
					t.Fatalf("step %d: %v", s.Version, err)
				}
			}
		}
		if !strings.Contains(string(body), s.Table) || !strings.Contains(string(body), s.Column) {
			t.Errorf("step %d does not create %s.%s", s.Version, s.Table, s.Column)
		}
	}
}

// TestWaveLineageFork stages the three node databases the merged build meets
// (2026-10-25 plans merge of the wave line) and holds the runner to the plan
// each needs:
//
//   - wave-built (pre-ledger, version 177 from guard_action_anchor): the plans
//     line's 177-196 run, 197 is adopted and the anchor column keeps its data;
//   - plans-line (ledger at 196, and the pre-ledger shape of the same
//     database): 197 runs, plus the steps above it (198), and nothing else;
//   - fresh: every step runs.
//
// The lineage head is read from the lineage (198, hook_activity, when the
// fork was merged); every step above 197 is an ordinary step that runs after
// the fork on each database, so a new migration needs no edit here.
func TestWaveLineageFork(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	head := LatestSchemaVersion()
	if head < 198 {
		t.Fatalf("lineage head = %d; this test stages the 197 merge under a head of at least 198", head)
	}
	headStr := strconv.Itoa(head)
	// aboveFork is every embedded step after the fork, 198 up to the head.
	entries, err := readMigrationEntries()
	if err != nil {
		t.Fatal(err)
	}
	var aboveFork []int
	for _, e := range entries {
		if e.version > 197 {
			aboveFork = append(aboveFork, e.version)
		}
	}

	t.Run("wave-built database", func(t *testing.T) {
		t.Parallel()
		d := ledgertest.OpenRaw(t)
		if err := nodeRunner(ctx, d, waveLineage(t), nil); err != nil {
			t.Fatalf("wave build: %v", err)
		}
		// A wave binary predates the per-step ledger: it leaves only the
		// version record.
		ledgertest.StripLedger(t, d)
		if v, _ := Version(ctx, d); v != 177 {
			t.Fatalf("wave database version = %d, want 177", v)
		}
		if !hasColumn(ctx, t, d, "guard_events", "action_anchor") || hasColumn(ctx, t, d, "sec_findings", "local_key") {
			t.Fatal("staged database is not wave-shaped")
		}
		mustExec := func(q string) {
			t.Helper()
			if _, err := d.ExecContext(ctx, q); err != nil {
				t.Fatalf("%s: %v", q, err)
			}
		}
		mustExec(`INSERT INTO guard_events (ts, rule_id, chain_prev, chain_hash, action_anchor)
			VALUES ('2026-10-22T00:00:00Z', 'R-101', '', 'h1', 42)`)
		mustExec(`INSERT INTO projects (id, root_path, created_at) VALUES (1, '/p', '2026-10-22T00:00:00Z')`)
		mustExec(`INSERT INTO sessions (id, project_id, tool, started_at, total_actions)
			VALUES ('s-autohand', 1, 'autohand', '2026-10-22T00:00:00Z', 0)`)
		mustExec(`INSERT INTO actions (session_id, project_id, timestamp, action_type, tool, raw_tool_name, source_file, source_event_id)
			VALUES ('s-autohand', 1, '2026-10-22T01:00:00Z', 'unknown', 'autohand', 'read_file', 'seed.jsonl', 'e1')`)

		// Without the probes the runner would adopt the plans line's 177 under
		// the pre-ledger horizon and re-run the anchor ALTER (which fails on
		// the existing column).
		if got := planFrom(ctx, t, d, migrations.Files, nil).RunVersions(); len(got) == 0 || got[0] != 178 || got[len(got)-1] != head {
			t.Fatalf("without the probes the plan runs %v, want 178..%d (the fork this table closes)", got, head)
		}
		var withProbes []int
		for v := 177; v <= 196; v++ {
			withProbes = append(withProbes, v)
		}
		withProbes = append(withProbes, aboveFork...)
		if got := planFrom(ctx, t, d, migrations.Files, lateSteps).RunVersions(); !reflect.DeepEqual(got, withProbes) {
			t.Fatalf("with the probes the plan runs %v, want %v", got, withProbes)
		}

		if err := nodeRunner(ctx, d, migrations.Files, lateSteps); err != nil {
			t.Fatalf("merged build on a wave database: %v", err)
		}
		meta := ledgertest.Meta(t, d)
		if meta["version"] != headStr {
			t.Fatalf("version = %q, want the head %d", meta["version"], head)
		}
		for _, v := range aboveFork {
			if meta[migplan.StepKey(v)] != migplan.RecordApplied {
				t.Errorf("migration:%d = %q, want applied", v, meta[migplan.StepKey(v)])
			}
		}
		for v := 177; v <= 196; v++ {
			if meta[migplan.StepKey(v)] != migplan.RecordApplied {
				t.Errorf("migration:%d = %q, want applied", v, meta[migplan.StepKey(v)])
			}
		}
		for _, v := range []int{1, 77, 176, 197} {
			if meta[migplan.StepKey(v)] != migplan.RecordAdopted {
				t.Errorf("migration:%d = %q, want adopted", v, meta[migplan.StepKey(v)])
			}
		}
		if !hasColumn(ctx, t, d, "sec_findings", "local_key") || !hasColumn(ctx, t, d, "terminal_run", "evidence_seal_sig") {
			t.Error("the plans line's 177-196 objects are missing after the merged run")
		}
		var anchor int
		if err := d.QueryRowContext(ctx, `SELECT action_anchor FROM guard_events WHERE chain_hash = 'h1'`).Scan(&anchor); err != nil || anchor != 42 {
			t.Errorf("guard_events.action_anchor = %d (%v), want 42 kept", anchor, err)
		}
		var at string
		if err := d.QueryRowContext(ctx, `SELECT action_type FROM actions WHERE source_event_id = 'e1'`).Scan(&at); err != nil || at != "read_file" {
			t.Errorf("autohand read_file = %q (%v), want read_file from 196", at, err)
		}
		// A second start plans nothing.
		if plan := planFrom(ctx, t, d, migrations.Files, lateSteps); !plan.Noop() {
			t.Fatalf("second start plans %+v, want nothing", plan)
		}
	})

	for _, tc := range []struct {
		name      string
		preLedger bool
	}{
		{name: "plans-line database with a ledger"},
		{name: "plans-line database without a ledger", preLedger: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d := ledgertest.OpenRaw(t)
			if err := nodeRunner(ctx, d, lineageThrough(t, 196), lateSteps); err != nil {
				t.Fatalf("plans build: %v", err)
			}
			if tc.preLedger {
				ledgertest.StripLedger(t, d)
			}
			before, err := AppliedSteps(ctx, d)
			if err != nil {
				t.Fatal(err)
			}
			want := append([]int{197}, aboveFork...)
			if got := planFrom(ctx, t, d, migrations.Files, lateSteps).RunVersions(); !reflect.DeepEqual(got, want) {
				t.Fatalf("plan runs %v, want %v", got, want)
			}
			if err := nodeRunner(ctx, d, migrations.Files, lateSteps); err != nil {
				t.Fatalf("merged run: %v", err)
			}
			if after, _ := AppliedSteps(ctx, d); after-before != len(want) {
				t.Errorf("applied steps %d -> %d, want exactly %v run", before, after, want)
			}
			meta := ledgertest.Meta(t, d)
			if meta["version"] != headStr || meta[migplan.StepKey(197)] != migplan.RecordApplied {
				t.Errorf("version=%q migration:197=%q, want version %d and 197 applied", meta["version"], meta[migplan.StepKey(197)], head)
			}
			if tc.preLedger && meta[migplan.StepKey(177)] != migplan.RecordAdopted {
				t.Errorf("migration:177 = %q, want adopted (its objects are present)", meta[migplan.StepKey(177)])
			}
			if !hasColumn(ctx, t, d, "guard_events", "action_anchor") {
				t.Error("guard_events.action_anchor missing")
			}
		})
	}

	t.Run("fresh database", func(t *testing.T) {
		t.Parallel()
		d := ledgertest.OpenRaw(t)
		if err := nodeRunner(ctx, d, migrations.Files, lateSteps); err != nil {
			t.Fatalf("fresh run: %v", err)
		}
		meta := ledgertest.Meta(t, d)
		if meta["version"] != headStr {
			t.Fatalf("version = %q, want the head %d", meta["version"], head)
		}
		for _, v := range []int{1, 176, 177, 196, 197, 198, head} {
			if meta[migplan.StepKey(v)] != migplan.RecordApplied {
				t.Errorf("migration:%d = %q, want applied", v, meta[migplan.StepKey(v)])
			}
		}
	})
}
