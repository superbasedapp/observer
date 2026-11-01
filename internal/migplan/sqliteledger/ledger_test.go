package sqliteledger_test

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"reflect"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/migplan"
	"github.com/marmutapp/superbased-observer/internal/migplan/sqliteledger"
	"github.com/marmutapp/superbased-observer/internal/migplan/sqliteledger/ledgertest"
)

// minimalRunner is the smallest runner a SQLite store can build on the
// package: one pinned connection, BEGIN IMMEDIATE, Plan, Apply, COMMIT.
func minimalRunner(ctx context.Context, db *sql.DB, source fs.FS, late []migplan.LateStep) error {
	names, err := fs.Glob(source, "*.sql")
	if err != nil {
		return err
	}
	byVersion := map[int]string{}
	var embedded []int
	for _, n := range names { // fs.Glob sorts, and the names are zero-padded.
		v := 0
		for _, c := range strings.SplitN(n, "_", 2)[0] {
			v = v*10 + int(c-'0')
		}
		embedded = append(embedded, v)
		byVersion[v] = n
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)`); err != nil {
		return err
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(ctx, "ROLLBACK")
		}
	}()
	plan, err := sqliteledger.Plan(ctx, conn, embedded, late)
	if err != nil {
		return err
	}
	if err := sqliteledger.Apply(ctx, conn, plan, func(v int) error {
		body, err := fs.ReadFile(source, byVersion[v])
		if err != nil {
			return err
		}
		if _, err := conn.ExecContext(ctx, string(body)); err != nil {
			return wrapf("exec "+byVersion[v], err)
		}
		return nil
	}); err != nil {
		return wrapf("minimal.runMigrations", err)
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return err
	}
	committed = true
	return nil
}

func wrapf(msg string, err error) error { return fmt.Errorf("%s: %w", msg, err) }

func TestScenariosOnAMinimalRunner(t *testing.T) {
	ledgertest.Scenarios(t, "minimal.runMigrations", minimalRunner)
}

func TestReadLedger(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		rows    map[string]string
		noTable bool
		want    migplan.Ledger
		wantErr string
	}{
		{name: "no schema_meta table is an empty ledger", noTable: true, want: migplan.Ledger{Steps: map[int]string{}}},
		{
			name: "foreign keys around the step range are not read",
			rows: map[string]string{
				"version": "7", migplan.HorizonKey: "5", "migration:6": migplan.RecordApplied,
				"migration_079_max_action_id": "x", "migrationz": "x", "integrity_verdict": "{}",
			},
			want: migplan.Ledger{Version: 7, HasHorizon: true, Horizon: 5, Steps: map[int]string{6: migplan.RecordApplied}},
		},
		{name: "malformed step value is an error", rows: map[string]string{"migration:2": "maybe"}, wantErr: "invalid step record"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := ledgertest.OpenRaw(t)
			if !tc.noTable {
				if _, err := db.ExecContext(ctx, `CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)`); err != nil {
					t.Fatal(err)
				}
				for k, v := range tc.rows {
					if _, err := db.ExecContext(ctx, `INSERT INTO schema_meta(key, value) VALUES (?, ?)`, k, v); err != nil {
						t.Fatal(err)
					}
				}
			}
			got, err := sqliteledger.ReadLedger(ctx, db)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %+v want %+v", got, tc.want)
			}
		})
	}
}

func TestProbeLateOnlyProbesEmbeddedSteps(t *testing.T) {
	ctx := context.Background()
	db := ledgertest.OpenRaw(t)
	if _, err := db.ExecContext(ctx, `CREATE TABLE a (id INTEGER, late_col INTEGER)`); err != nil {
		t.Fatal(err)
	}
	late := []migplan.LateStep{
		{Version: 3, Table: "a", Column: "late_col"},
		{Version: 4, Table: "a", Column: "missing_col"},
		{Version: 9, Table: "a", Column: "late_col"},
	}
	got, err := sqliteledger.ProbeLate(ctx, db, late, []int{1, 3, 4})
	if err != nil {
		t.Fatal(err)
	}
	if want := map[int]bool{3: true, 4: false}; !reflect.DeepEqual(got, want) {
		t.Fatalf("probe = %v, want %v", got, want)
	}
	if got, err := sqliteledger.ProbeLate(ctx, db, nil, []int{1}); err != nil || len(got) != 0 {
		t.Fatalf("empty late table probed %v, %v", got, err)
	}
}

func TestAppliedCountIgnoresAdoptedSteps(t *testing.T) {
	ctx := context.Background()
	db := ledgertest.OpenRaw(t)
	if n, err := sqliteledger.AppliedCount(ctx, db); err != nil || n != 0 {
		t.Fatalf("no schema_meta: %d, %v", n, err)
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{
		"version": "4", migplan.HorizonKey: "3",
		"migration:1": migplan.RecordAdopted, "migration:2": migplan.RecordAdopted,
		"migration:3": migplan.RecordApplied, "migration:4": migplan.RecordApplied,
	} {
		if _, err := db.ExecContext(ctx, `INSERT INTO schema_meta(key, value) VALUES (?, ?)`, k, v); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := sqliteledger.AppliedCount(ctx, db); err != nil || n != 2 {
		t.Fatalf("AppliedCount = %d, %v; want 2", n, err)
	}
}
