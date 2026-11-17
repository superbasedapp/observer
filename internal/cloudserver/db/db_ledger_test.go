package db

// db_ledger_test.go covers the cloud runner's per-step ledger (lane W9-L6):
// the runner plans through internal/migplan and applies every embedded step
// that has no sbci_migrations row, including one numbered below the highest
// recorded version, so a step that lands late from a parallel line is never
// skipped on a database that already moved past its number.

import (
	"context"
	"io/fs"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/db/migrations"
)

func TestPlanPending(t *testing.T) {
	t.Parallel()
	lineage := func(versions ...int) []entry {
		out := make([]entry, len(versions))
		for i, v := range versions {
			out[i] = entry{version: v, filename: "x"}
		}
		return out
	}
	set := func(versions ...int) map[int]bool {
		out := map[int]bool{}
		for _, v := range versions {
			out[v] = true
		}
		return out
	}
	for _, tc := range []struct {
		name     string
		entries  []entry
		recorded map[int]bool
		want     []int
		wantErr  string
	}{
		{name: "fresh database runs every step", entries: lineage(1, 2, 3), recorded: set(), want: []int{1, 2, 3}},
		{name: "steps above the head run", entries: lineage(1, 2, 3, 4), recorded: set(1, 2), want: []int{3, 4}},
		{name: "a late step below the head runs", entries: lineage(1, 2, 3, 4), recorded: set(1, 2, 4), want: []int{3}},
		{name: "late steps and new steps run in version order", entries: lineage(1, 2, 3, 4, 5, 6), recorded: set(1, 3, 4), want: []int{2, 5, 6}},
		{name: "a gap in the lineage is not a step", entries: lineage(1, 2, 5), recorded: set(1, 2), want: []int{5}},
		{name: "fully migrated database runs nothing", entries: lineage(1, 2, 3), recorded: set(1, 2, 3), want: nil},
		{name: "rows from a newer binary are ignored", entries: lineage(1, 2), recorded: set(1, 2, 3, 9), want: nil},
		{name: "a newer binary's rows do not hide an older step", entries: lineage(1, 2, 3), recorded: set(1, 3, 9), want: []int{2}},
		{name: "a duplicate version is refused", entries: lineage(1, 2, 2), recorded: set(), wantErr: "strictly ascending"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := planPending(tc.entries, tc.recorded)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("planPending err = %v, want one containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("planPending: %v", err)
			}
			var versions []int
			for _, e := range got {
				versions = append(versions, e.version)
			}
			if !reflect.DeepEqual(versions, tc.want) {
				t.Fatalf("planPending = %v, want %v", versions, tc.want)
			}
		})
	}
}

// TestMigrateAppliesLateLowerStepOnMigratedDatabase stages the hazard the old
// runner had: a database already at the head of the real lineage (above 0079)
// meets a build whose lineage gained a step numbered in a gap below the head
// (0077, never used). The step runs, is recorded with its label, the head is
// unchanged, and a rerun is a no-op.
func TestMigrateAppliesLateLowerStepOnMigratedDatabase(t *testing.T) {
	t.Parallel()
	pool := newThrowawayDB(t, "sbci_w9l6_late_")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate to head: %v", err)
	}
	head, err := MaxEmbeddedVersion()
	if err != nil {
		t.Fatal(err)
	}
	const late = 77
	if head <= late {
		t.Fatalf("lineage head %d is not above the staged late step %d", head, late)
	}
	if _, applied, err := StepLabel(ctx, pool, late); err != nil || applied {
		t.Fatalf("step %d already recorded (applied=%v err=%v); pick an unused number below the head", late, applied, err)
	}

	// The real lineage plus one late step in its gap.
	overlay := fstest.MapFS{}
	des, err := fs.ReadDir(migrations.Files, ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, de := range des {
		if !strings.HasSuffix(de.Name(), ".sql") {
			continue
		}
		body, err := fs.ReadFile(migrations.Files, de.Name())
		if err != nil {
			t.Fatal(err)
		}
		overlay[de.Name()] = &fstest.MapFile{Data: body}
	}
	overlay["0077_w9l6_late_probe.sql"] = &fstest.MapFile{Data: []byte(
		"-- step: expand\nSET LOCAL lock_timeout = '5s';\nCREATE TABLE w9l6_late_probe (id int);\n")}
	entries, err := readEntriesFrom(overlay)
	if err != nil {
		t.Fatal(err)
	}

	if err := migrateEntries(ctx, pool, MigrateOptions{}, overlay, entries); err != nil {
		t.Fatalf("migrate with a late step below the head: %v", err)
	}
	var exists bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass('public.w9l6_late_probe') IS NOT NULL`).Scan(&exists); err != nil || !exists {
		t.Fatalf("late step's table exists = %v err=%v, want true (the step was skipped)", exists, err)
	}
	if got, applied, err := StepLabel(ctx, pool, late); err != nil || !applied || got != "expand" {
		t.Fatalf("StepLabel(%d) = %q applied=%v err=%v, want expand", late, got, applied, err)
	}
	if v, err := Version(ctx, pool); err != nil || v != head {
		t.Fatalf("Version = %d err=%v, want the unchanged head %d", v, err, head)
	}

	// A rerun applies nothing: the late step would fail on its existing table.
	if err := migrateEntries(ctx, pool, MigrateOptions{}, overlay, entries); err != nil {
		t.Fatalf("rerun after the late step: %v", err)
	}
	// And the production lineage on its own still sees nothing pending.
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate after the late step: %v", err)
	}
}

// TestMigrateRunsLateStepBeforeNewerOnes pins the order with a late step:
// steps 1, 2 and 4 are applied, then a lineage gaining 3 and 5 runs 3 first
// and 5 after it, each in its own transaction.
func TestMigrateRunsLateStepBeforeNewerOnes(t *testing.T) {
	t.Parallel()
	pool := newThrowawayDB(t, "sbci_w9l6_order_")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	first := fstest.MapFS{
		"0001_a.sql": {Data: []byte("-- step: expand\nCREATE TABLE w9l6_log (v int, at serial);\n")},
		"0002_b.sql": {Data: []byte("-- step: data\nINSERT INTO w9l6_log (v) VALUES (2);\n")},
		"0004_d.sql": {Data: []byte("-- step: data\nINSERT INTO w9l6_log (v) VALUES (4);\n")},
	}
	entries, err := readEntriesFrom(first)
	if err != nil {
		t.Fatal(err)
	}
	if err := migrateEntries(ctx, pool, MigrateOptions{}, first, entries); err != nil {
		t.Fatalf("first lineage: %v", err)
	}

	second := fstest.MapFS{
		"0001_a.sql": first["0001_a.sql"],
		"0002_b.sql": first["0002_b.sql"],
		"0003_c.sql": {Data: []byte("-- step: data\nINSERT INTO w9l6_log (v) VALUES (3);\n")},
		"0004_d.sql": first["0004_d.sql"],
		"0005_e.sql": {Data: []byte("-- step: data\nINSERT INTO w9l6_log (v) VALUES (5);\n")},
	}
	entries, err = readEntriesFrom(second)
	if err != nil {
		t.Fatal(err)
	}
	if err := migrateEntries(ctx, pool, MigrateOptions{}, second, entries); err != nil {
		t.Fatalf("second lineage: %v", err)
	}
	rows, err := pool.Query(ctx, `SELECT v FROM w9l6_log ORDER BY at`)
	if err != nil {
		t.Fatal(err)
	}
	var got []int
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		got = append(got, v)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if want := []int{2, 4, 3, 5}; !reflect.DeepEqual(got, want) {
		t.Fatalf("applied order = %v, want %v (each step once; the late 3 before the new 5)", got, want)
	}
	if v, err := Version(ctx, pool); err != nil || v != 5 {
		t.Fatalf("Version = %d err=%v, want 5", v, err)
	}
}
