// Package ledgertest drives a SQLite migration runner that uses the per-step
// ledger (internal/migplan, internal/migplan/sqliteledger) through one table
// of scenarios, so every runner (the node, the edge WAL, the cold archive) is
// held to the same contract by the same cases. It is test support only:
// production code must not import it.
package ledgertest

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/marmutapp/superbased-observer/internal/migplan"

	_ "modernc.org/sqlite" // sqlite driver registration.
)

// Runner is a migration runner under test, over an explicit lineage and
// late-step table.
type Runner func(ctx context.Context, db *sql.DB, source fs.FS, late []migplan.LateStep) error

// stepBodies is the synthetic lineage. Every step logs itself into ran(v)
// first, so a test can count executions; the ALTERs are deliberately not
// idempotent, so a step that wrongly runs twice fails loudly.
var stepBodies = map[int]string{
	1: `CREATE TABLE IF NOT EXISTS ran (v INTEGER NOT NULL); INSERT INTO ran(v) VALUES (1); CREATE TABLE a (id INTEGER);`,
	2: `INSERT INTO ran(v) VALUES (2); ALTER TABLE a ADD COLUMN b INTEGER;`,
	3: `INSERT INTO ran(v) VALUES (3); ALTER TABLE a ADD COLUMN late_col INTEGER;`,
	4: `INSERT INTO ran(v) VALUES (4); CREATE TABLE d (id INTEGER);`,
}

// failingLate is a step 3 that logs itself and then fails, so a test can see
// that the log row was rolled back with it.
const failingLate = `INSERT INTO ran(v) VALUES (3); ALTER TABLE missing_table ADD COLUMN x INTEGER;`

// lateProbe is the LateStep row for synthetic step 3.
var lateProbe = []migplan.LateStep{{Version: 3, Table: "a", Column: "late_col"}}

// Lineage returns the synthetic lineage holding versions.
func Lineage(versions ...int) fstest.MapFS {
	m := fstest.MapFS{}
	for _, v := range versions {
		m[fileName(v)] = &fstest.MapFile{Data: []byte(stepBodies[v])}
	}
	return m
}

func fileName(v int) string {
	if v == 3 {
		return "003_late.sql"
	}
	return fmt.Sprintf("%03d_step.sql", v)
}

// OpenRaw opens a database file in a fresh temp dir with no migrations run.
func OpenRaw(t *testing.T) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ledger.db")
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(10000)&_pragma=foreign_keys(1)&_txlock=immediate")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.PingContext(context.Background()); err != nil {
		t.Fatalf("ping: %v", err)
	}
	return db
}

// StripLedger turns a ledger database back into a pre-ledger one: it deletes
// the per-step records and the horizon and keeps only 'version', which is
// what a runner older than T-979 left behind.
func StripLedger(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(),
		`DELETE FROM schema_meta WHERE key = ? OR (key >= ? AND key < ?)`,
		migplan.HorizonKey, migplan.StepKeyPrefix, "migration;"); err != nil {
		t.Fatalf("strip ledger: %v", err)
	}
}

// Meta returns schema_meta as a map.
func Meta(t *testing.T, db *sql.DB) map[string]string {
	t.Helper()
	rows, err := db.QueryContext(context.Background(), `SELECT key, value FROM schema_meta`)
	if err != nil {
		t.Fatalf("read schema_meta: %v", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			t.Fatalf("scan schema_meta: %v", err)
		}
		out[k] = v
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("schema_meta rows: %v", err)
	}
	return out
}

// runs counts ran(v) rows per version (empty before step 1 ever ran).
func runs(t *testing.T, db *sql.DB) map[int]int {
	t.Helper()
	out := map[int]int{}
	var n int
	if err := db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'ran'`).Scan(&n); err != nil {
		t.Fatalf("inspect ran: %v", err)
	}
	if n == 0 {
		return out
	}
	rows, err := db.QueryContext(context.Background(), `SELECT v, COUNT(*) FROM ran GROUP BY v`)
	if err != nil {
		t.Fatalf("read ran: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var v, c int
		if err := rows.Scan(&v, &c); err != nil {
			t.Fatalf("scan ran: %v", err)
		}
		out[v] = c
	}
	return out
}

// records projects schema_meta's per-step records.
func records(meta map[string]string) map[int]string {
	out := map[int]string{}
	for k, v := range meta {
		if strings.HasPrefix(k, migplan.StepKeyPrefix) {
			n, _ := strconv.Atoi(strings.TrimPrefix(k, migplan.StepKeyPrefix))
			out[n] = v
		}
	}
	return out
}

const (
	applied = migplan.RecordApplied
	adopted = migplan.RecordAdopted
)

// Scenarios runs the shared table against run. errPrefix is the runner's own
// error prefix (for example "db.runMigrations"); the failing case expects
// "<errPrefix>: exec 003_late.sql".
func Scenarios(t *testing.T, errPrefix string, run Runner) {
	ctx := context.Background()
	must := func(t *testing.T, db *sql.DB, src fs.FS, late []migplan.LateStep) {
		t.Helper()
		if err := run(ctx, db, src, late); err != nil {
			t.Fatalf("setup run: %v", err)
		}
	}
	full := func() fs.FS { return Lineage(1, 2, 3, 4) }
	for _, tc := range []struct {
		name        string
		setup       func(t *testing.T, db *sql.DB)
		source      fs.FS
		late        []migplan.LateStep
		wantRan     []int
		wantRecords map[int]string
		wantVersion string
		wantHorizon string
		wantErr     string
	}{
		{
			name:        "fresh database runs every step and records each",
			setup:       func(*testing.T, *sql.DB) {},
			source:      full(),
			wantRan:     []int{1, 2, 3, 4},
			wantRecords: map[int]string{1: applied, 2: applied, 3: applied, 4: applied},
			wantVersion: "4", wantHorizon: "0",
		},
		{
			name:        "contiguous ledger at head re-runs nothing",
			setup:       func(t *testing.T, db *sql.DB) { must(t, db, full(), nil) },
			source:      full(),
			wantRecords: map[int]string{1: applied, 2: applied, 3: applied, 4: applied},
			wantVersion: "4", wantHorizon: "0",
		},
		{
			name:        "ledger at 4 without step 3 runs only 3",
			setup:       func(t *testing.T, db *sql.DB) { must(t, db, Lineage(1, 2, 4), nil) },
			source:      full(),
			wantRan:     []int{3},
			wantRecords: map[int]string{1: applied, 2: applied, 3: applied, 4: applied},
			wantVersion: "4", wantHorizon: "0",
		},
		{
			name:        "ledger that did run step 3 runs nothing even with a late row",
			setup:       func(t *testing.T, db *sql.DB) { must(t, db, full(), nil) },
			source:      full(),
			late:        lateProbe,
			wantRecords: map[int]string{1: applied, 2: applied, 3: applied, 4: applied},
			wantVersion: "4", wantHorizon: "0",
		},
		{
			name: "pre-ledger database at 4 that never ran listed late step 3 runs it",
			setup: func(t *testing.T, db *sql.DB) {
				must(t, db, Lineage(1, 2, 4), nil)
				StripLedger(t, db)
			},
			source:      full(),
			late:        lateProbe,
			wantRan:     []int{3},
			wantRecords: map[int]string{1: adopted, 2: adopted, 3: applied, 4: adopted},
			wantVersion: "4", wantHorizon: "4",
		},
		{
			name: "pre-ledger database at 4 that did run listed late step 3 runs nothing",
			setup: func(t *testing.T, db *sql.DB) {
				must(t, db, full(), nil)
				StripLedger(t, db)
			},
			source:      full(),
			late:        lateProbe,
			wantRecords: map[int]string{1: adopted, 2: adopted, 3: adopted, 4: adopted},
			wantVersion: "4", wantHorizon: "4",
		},
		{
			name: "pre-ledger database adopts an unlisted lower step (the old rule, why lateSteps exists)",
			setup: func(t *testing.T, db *sql.DB) {
				must(t, db, Lineage(1, 2, 4), nil)
				StripLedger(t, db)
			},
			source:      full(),
			wantRecords: map[int]string{1: adopted, 2: adopted, 3: adopted, 4: adopted},
			wantVersion: "4", wantHorizon: "4",
		},
		{
			name:  "failing late step rolls the whole pass back with a wrapped error",
			setup: func(t *testing.T, db *sql.DB) { must(t, db, Lineage(1, 2, 4), nil) },
			source: func() fs.FS {
				m := Lineage(1, 2, 4)
				m["003_late.sql"] = &fstest.MapFile{Data: []byte(failingLate)}
				return m
			}(),
			wantErr: errPrefix + ": exec 003_late.sql",
			// Nothing of the failed pass survives: no run of 3, no record.
			wantRecords: map[int]string{1: applied, 2: applied, 4: applied},
			wantVersion: "4", wantHorizon: "0",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := OpenRaw(t)
			tc.setup(t, db)
			before := runs(t, db)
			err := run(ctx, db, tc.source, tc.late)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("run: %v", err)
			case tc.wantErr != "":
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
				}
				if errors.Unwrap(err) == nil {
					t.Fatalf("err %v does not wrap its cause", err)
				}
			}
			after := runs(t, db)
			var ran []int
			for v := 1; v <= 4; v++ {
				if after[v]-before[v] > 0 {
					ran = append(ran, v)
				}
				if after[v] > 1 {
					t.Errorf("step %d executed %d times in total", v, after[v])
				}
			}
			if !reflect.DeepEqual(ran, tc.wantRan) {
				t.Errorf("steps run = %v, want %v", ran, tc.wantRan)
			}
			meta := Meta(t, db)
			if got := records(meta); !reflect.DeepEqual(got, tc.wantRecords) {
				t.Errorf("step records = %v, want %v", got, tc.wantRecords)
			}
			if meta[migplan.VersionKey] != tc.wantVersion || meta[migplan.HorizonKey] != tc.wantHorizon {
				t.Errorf("version %q horizon %q, want %q / %q",
					meta[migplan.VersionKey], meta[migplan.HorizonKey], tc.wantVersion, tc.wantHorizon)
			}
		})
	}
}

// PreLedgerReopen runs the runner's REAL lineage on a fresh database, turns
// it into a pre-ledger database, and runs it again: every step must be
// adopted (none executed, and a re-executed non-idempotent step would fail),
// with the horizon and version at the lineage head.
func PreLedgerReopen(t *testing.T, run Runner, source fs.FS, late []migplan.LateStep) {
	t.Helper()
	ctx := context.Background()
	db := OpenRaw(t)
	if err := run(ctx, db, source, late); err != nil {
		t.Fatalf("fresh run of the real lineage: %v", err)
	}
	head := Meta(t, db)[migplan.VersionKey]
	StripLedger(t, db)
	if err := run(ctx, db, source, late); err != nil {
		t.Fatalf("pre-ledger reopen: %v", err)
	}
	meta := Meta(t, db)
	if meta[migplan.VersionKey] != head || meta[migplan.HorizonKey] != head {
		t.Fatalf("pre-ledger reopen: version %q horizon %q, want %s / %s",
			meta[migplan.VersionKey], meta[migplan.HorizonKey], head, head)
	}
	entries, err := fs.Glob(source, "*.sql")
	if err != nil || len(entries) == 0 {
		t.Fatalf("lineage listing: %v (%d files)", err, len(entries))
	}
	recs := records(meta)
	for _, name := range entries {
		v, err := strconv.Atoi(strings.SplitN(name, "_", 2)[0])
		if err != nil {
			t.Fatalf("lineage file %q: %v", name, err)
		}
		if recs[v] != adopted {
			t.Errorf("step %d record = %q, want %q", v, recs[v], adopted)
		}
	}
	if len(recs) != len(entries) {
		t.Errorf("%d step records for %d lineage files", len(recs), len(entries))
	}
}
