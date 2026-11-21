package main

import (
	"bytes"
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestFormatGuardAnchorProgress: the stderr progress line, per state.
func TestFormatGuardAnchorProgress(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		p    store.GuardAnchorProgress
		want string
	}{
		{
			"nothing searched yet",
			store.GuardAnchorProgress{Candidates: 10},
			"repair-anchors: 0/10 row(s) searched, 0 proven, 0 unproven, 0s elapsed",
		},
		{
			"midway, with rate and ETA",
			store.GuardAnchorProgress{Done: 25, Candidates: 100, Proven: 20, Unproven: 5, Hashed: 30_000_000, Elapsed: 10 * time.Second},
			"repair-anchors: 25/100 row(s) searched, 20 proven, 5 unproven, 3.0M hashes/s, ETA 30s, 10s elapsed",
		},
		{
			"all searched: no ETA",
			store.GuardAnchorProgress{Done: 4, Candidates: 4, Proven: 4, Hashed: 1500, Elapsed: time.Second},
			"repair-anchors: 4/4 row(s) searched, 4 proven, 0 unproven, 1.5k hashes/s, 1s elapsed",
		},
	}
	for _, tc := range cases {
		if got := formatGuardAnchorProgress(tc.p); got != tc.want {
			t.Errorf("%s:\n got %q\nwant %q", tc.name, got, tc.want)
		}
	}
}

// TestGuardAnchorDistanceLabels: one label per store bucket, in order.
func TestGuardAnchorDistanceLabels(t *testing.T) {
	t.Parallel()
	got := strings.Join(guardAnchorDistanceLabels(), " ")
	want := "0 1-10 11-100 101-1000 1001-10000 10001-100000 100001-1000000 >1000000"
	if got != want {
		t.Fatalf("labels = %q, want %q", got, want)
	}
}

// TestWriteGuardAnchorReport: the report text for a complete, a bounded and
// an interrupted run.
func TestWriteGuardAnchorReport(t *testing.T) {
	t.Parallel()
	distances := map[string][]int{
		store.GuardAnchorHintSession: {0, 3, 0, 0, 0, 0, 0, 0},
		store.GuardAnchorHintContent: {7, 0, 0, 0, 0, 0, 0, 0},
	}
	cases := []struct {
		name     string
		r        store.GuardAnchorRepairReport
		contains []string
		absent   []string
	}{
		{
			name: "complete, whole range",
			r: store.GuardAnchorRepairReport{
				Candidates: 10, Proven: 10, Ceiling: 500, Workers: 2, Tries: 40, Hashed: 41,
				Elapsed: 1500 * time.Millisecond, Distances: distances,
			},
			contains: []string{
				"10 row(s) fail as rewritten with no action id; 10 proven (action ids 1-500, the whole range; 40 id(s) tried, 41 hash(es) on 2 worker(s) in 1.5s)",
				"proven, by the hint that found them and the distance from it:\n  same content: 0: 7\n  same session: 1-10: 3\n",
			},
			absent: []string{"not proven", "interrupted"},
		},
		{
			name: "bounded, with misses",
			r: store.GuardAnchorRepairReport{
				Candidates: 3, Proven: 1, Ceiling: 9000, Radius: 100, Workers: 1,
				Distances:     map[string][]int{store.GuardAnchorHintFirst: {0, 0, 0, 1, 0, 0, 0, 0}},
				UnprovenCount: 2, UnprovenByReason: map[string]int{store.GuardAnchorOutsideRadius: 1, store.GuardAnchorNoID: 1},
				Unproven: []store.GuardAnchorUnproven{
					{ID: 4, Hint: 500, Lo: 400, Hi: 600, Windows: 3, Reason: store.GuardAnchorOutsideRadius},
					{ID: 9, Reason: store.GuardAnchorNoID},
				},
			},
			contains: []string{
				"within 100 of each row's hint",
				"  first action id: 101-1000: 1\n",
				"2 not proven (left as reported):\n  1: " + store.GuardAnchorNoID + "\n  1: " + store.GuardAnchorOutsideRadius + "\n",
				"  id 4: searched 400-600 around 500 and 2 more window(s): " + store.GuardAnchorOutsideRadius + "\n",
				"  id 9: " + store.GuardAnchorNoID + "\n",
				"a wider --radius (0 = every id up to the ceiling) searches those rows further",
			},
		},
		{
			name:     "interrupted",
			r:        store.GuardAnchorRepairReport{Candidates: 50, Proven: 4, UnprovenCount: 1, Interrupted: true, UnprovenByReason: map[string]int{store.GuardAnchorNoID: 1}},
			contains: []string{"interrupted after 5 of 50 candidate row(s): partial report, nothing written\n"},
			absent:   []string{"a wider --radius"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var out bytes.Buffer
			writeGuardAnchorReport(&out, tc.r)
			for _, s := range tc.contains {
				if !strings.Contains(out.String(), s) {
					t.Errorf("missing %q in:\n%s", s, out.String())
				}
			}
			for _, s := range tc.absent {
				if strings.Contains(out.String(), s) {
					t.Errorf("unexpected %q in:\n%s", s, out.String())
				}
			}
		})
	}
}

// TestGuardRepairAnchorsCmd drives `observer guard repair-anchors` against
// a real DB holding one row whose action id (far above its only hint, the
// first action id) maintenance cleared: a small radius reports it
// unproven with the reason and the way to widen, --radius 0 proves it, and
// --apply restores it so the chain verifies.
func TestGuardRepairAnchorsCmd(t *testing.T) {
	t.Parallel()
	cfgPath, dbPath := writeGuardTestConfig(t)
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	// One connection, foreign keys off: the row names an action this DB
	// never held, the way a pruned action's row did.
	database.SetMaxOpenConns(1)
	if _, err := database.ExecContext(ctx, `PRAGMA foreign_keys = OFF`); err != nil {
		t.Fatal(err)
	}
	const anchor = int64(50_000)
	action := anchor
	if _, err := store.New(database).InsertGuardEvents(ctx, []store.GuardEventRow{
		{
			TS: time.Date(2026, 5, 17, 9, 27, 35, 0, time.UTC), SessionID: "s1", ActionID: &action, Tool: "copilot",
			EventKind: "file_access", RuleID: "R-150", Decision: "flag", Severity: "high",
		},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := database.ExecContext(ctx, `UPDATE guard_events SET action_id = NULL, action_anchor = NULL`); err != nil {
		t.Fatal(err)
	}
	_ = database.Close()

	ceiling := "--ceiling=" + strconv.FormatInt(anchor+10, 10)
	out, err := runGuardCmd(t, "repair-anchors", "--config", cfgPath, ceiling, "--progress=0", "--radius=1000")
	if err != nil {
		t.Fatalf("bounded dry run: %v (%s)", err, out)
	}
	for _, want := range []string{"1 row(s) fail as rewritten with no action id; 0 proven", store.GuardAnchorOutsideRadius, "a wider --radius"} {
		if !strings.Contains(out, want) {
			t.Errorf("bounded dry run: missing %q in:\n%s", want, out)
		}
	}

	out, err = runGuardCmd(t, "repair-anchors", "--config", cfgPath, ceiling, "--progress=0", "--radius=0", "--workers=1")
	if err != nil {
		t.Fatalf("whole-range dry run: %v (%s)", err, out)
	}
	for _, want := range []string{"1 proven", "the whole range", "1 worker(s)", "first action id: 10001-100000: 1", "dry run: pass --apply"} {
		if !strings.Contains(out, want) {
			t.Errorf("whole-range dry run: missing %q in:\n%s", want, out)
		}
	}

	out, err = runGuardCmd(t, "repair-anchors", "--config", cfgPath, ceiling, "--progress=0", "--radius=0", "--apply")
	if err != nil {
		t.Fatalf("apply: %v (%s)", err, out)
	}
	for _, want := range []string{"restored 1 action id(s)", "audit chain OK - 1 row(s) verified"} {
		if !strings.Contains(out, want) {
			t.Errorf("apply: missing %q in:\n%s", want, out)
		}
	}
}

// TestGuardRepairAnchorsFlagDefaults pins the documented defaults.
func TestGuardRepairAnchorsFlagDefaults(t *testing.T) {
	t.Parallel()
	cmd := newGuardRepairAnchorsCmd()
	want := map[string]string{
		"radius":   "4194304",
		"workers":  strconv.Itoa(store.DefaultGuardAnchorWorkers()),
		"progress": "10s",
		"apply":    "false",
		"ceiling":  "0",
	}
	for name, def := range want {
		f := cmd.Flags().Lookup(name)
		if f == nil || f.DefValue != def {
			t.Errorf("--%s default = %v, want %s", name, f, def)
		}
	}
}
