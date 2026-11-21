package db

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/marmutapp/superbased-observer/internal/db/migrations"
	"github.com/marmutapp/superbased-observer/internal/migplan"
	"github.com/marmutapp/superbased-observer/internal/migplan/sqliteledger/ledgertest"
)

const backfill2File = "196_tooltax_action_type_backfill_2.sql"

// backfill3File is the third full backfill (PT-88): 196 shipped in v1.37.0
// and is frozen, so the tooltax rows added after it land here.
const backfill3File = "223_tooltax_action_type_backfill_3.sql"

// lineageWithout copies the embedded node lineage minus the named files.
func lineageWithout(t *testing.T, drop ...string) fstest.MapFS {
	t.Helper()
	skip := map[string]bool{}
	for _, d := range drop {
		skip[d] = true
	}
	out := fstest.MapFS{}
	des, err := fs.ReadDir(migrations.Files, ".")
	if err != nil {
		t.Fatalf("read lineage: %v", err)
	}
	for _, de := range des {
		if de.IsDir() || skip[de.Name()] {
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

// backfill2Case is one native name graded across the 077 -> 196 upgrade.
// want is the expected type after 196 ("" = only "not unknown", graded by
// the pre/post consistency check instead).
type backfill2Case struct {
	tool, raw string
	// after077 is the type the frozen 077 leaves on a row seeded unknown
	// before it ran.
	after077 string
	want     string
}

var backfill2Cases = []backfill2Case{
	// Names the newer tooltax table added after 077 shipped: 077 leaves them
	// unknown, 196 classifies them.
	{"crush", "job_kill", "unknown", "agent_control"},
	{"crush", "job_output", "unknown", "agent_control"},
	{"crush", "mcp_github_list", "unknown", "mcp_call"},
	{"crush", "agentic_fetch", "unknown", ""},
	{"goose", "read_image", "unknown", ""},
	{"kiro-cli", "goal", "unknown", "harness_call"},
	{"kiro-cli", "subagent", "unknown", "spawn_subagent"},
	{"kiro-cli", "use_aws", "unknown", ""},
	{"kiro-cli", "mcp_srv_tool", "unknown", "mcp_call"},
	// A name 077 already classified: 196 must leave it alone. crush
	// web_fetch is the precedence case: 077 named it through the tool-less
	// fallback, and 196's newer crush literal must agree with that.
	{"crush", "web_fetch", "web_fetch", "web_fetch"},
	{"codex", "wait", "subagent_wait", "subagent_wait"},
	{"claude-code", "Monitor", "agent_control", "agent_control"},
	// An unmapped name stays unknown through both.
	{"kiro-cli", "NoSuchTool", "unknown", "unknown"},
}

// backfill3Cases are the names the tooltax table added after 196 shipped
// (the Cursor run-stream calls of 489663da46): 077 and 196 leave them
// unknown, 223 classifies them.
var backfill3Cases = []backfill2Case{
	{"cursor", "communicate_update", "unknown", "harness_call"},
	{"cursor", "send_message", "unknown", "harness_call"},
	{"cursor", "run_terminal_cmd", "unknown", "run_command"},
	{"cursor", "file_search", "unknown", "search_files"},
	{"cursor", "create_agent", "unknown", "spawn_subagent"},
}

// TestMigration196ReRunsSafelyAfter077 grades the frozen-077 hand-over
// (D-880, T-982): a database that ran the v1.36.0 077 then gets 196, the
// full current backfill. 196 must classify only what 077 could not, never
// touch a row 077 or an adapter already classified, agree with what it does
// to a row ingested after 077 ran, and be a no-op when re-run (as must 077).
func TestMigration196ReRunsSafelyAfter077(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "backfill2.db")
	database, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(30000)&_pragma=foreign_keys(1)&_txlock=immediate")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer database.Close()

	// A v1.36.0-era database just before 077: every body below 077 replayed,
	// version pinned at 76 (pre-ledger, so the runner adopts 1-76).
	entries, err := readMigrationEntries()
	if err != nil {
		t.Fatalf("readMigrationEntries: %v", err)
	}
	if _, err := database.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)`); err != nil {
		t.Fatalf("bootstrap schema_meta: %v", err)
	}
	bodies := map[int]string{}
	for _, e := range entries {
		body, err := fs.ReadFile(migrations.Files, e.filename)
		if err != nil {
			t.Fatalf("read %s: %v", e.filename, err)
		}
		bodies[e.version] = string(body)
		if e.version < 77 {
			if _, err := database.ExecContext(ctx, string(body)); err != nil {
				t.Fatalf("apply %s: %v", e.filename, err)
			}
		}
	}
	if bodies[196] == "" || !strings.Contains(bodies[196], "WHY A SECOND STEP") {
		t.Fatalf("%s is not embedded or lacks its header", backfill2File)
	}
	if bodies[223] == "" || !strings.Contains(bodies[223], "WHY A THIRD STEP") {
		t.Fatalf("%s is not embedded or lacks its header", backfill3File)
	}
	allCases := append(append([]backfill2Case(nil), backfill2Cases...), backfill3Cases...)
	if _, err := database.ExecContext(ctx, `INSERT INTO schema_meta(key, value) VALUES ('version', '76')
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`); err != nil {
		t.Fatalf("pin version 76: %v", err)
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO projects (id, root_path, created_at) VALUES (1, '/p', '2026-07-01T00:00:00Z')`); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	seenTool := map[string]bool{}
	for _, c := range allCases {
		if seenTool[c.tool] {
			continue
		}
		seenTool[c.tool] = true
		if _, err := database.ExecContext(ctx, `INSERT INTO sessions (id, project_id, tool, started_at, total_actions)
			VALUES (?, 1, ?, '2026-07-01T00:00:00Z', 0)`, "sess-"+c.tool, c.tool); err != nil {
			t.Fatalf("seed session %s: %v", c.tool, err)
		}
	}
	seed := func(phase, before string, c backfill2Case) {
		t.Helper()
		id := fmt.Sprintf("%s|%s|%s", phase, c.tool, c.raw)
		if _, err := database.ExecContext(ctx, `INSERT INTO actions (session_id, project_id, timestamp, action_type, tool,
			   raw_tool_name, source_file, source_event_id)
			 VALUES (?, 1, '2026-07-01T01:00:00Z', ?, ?, ?, 'seed.jsonl', ?)`,
			"sess-"+c.tool, before, c.tool, c.raw, id); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}
	for _, c := range allCases {
		seed("pre", "unknown", c)
		// CONTROL: an adapter-classified row with the same name never moves.
		seed("classified", "post_tool_batch", c)
	}

	// The v1.36.0 upgrade: every step up to the head, including the frozen
	// 077, without the two later backfills.
	if err := runMigrationsFrom(ctx, database, defaultMigrationLockWait, lineageWithout(t, backfill2File, backfill3File), lateSteps); err != nil {
		t.Fatalf("run without 196 and 223: %v", err)
	}
	snap := taxBackfillSnapshot(ctx, t, database)
	for _, c := range allCases {
		if got := snap["pre|"+c.tool+"|"+c.raw]; got != c.after077 {
			t.Errorf("after 077: %s %s = %q, want %q", c.tool, c.raw, got, c.after077)
		}
	}
	// Rows a v1.36.0 adapter ingested after 077 ran, still unknown.
	for _, c := range backfill2Cases {
		seed("post", "unknown", c)
	}

	// The upgrade that carries 196: the runner applies exactly 196 (the
	// first pass already ran every other step, up to the head).
	if err := runMigrationsFrom(ctx, database, defaultMigrationLockWait, lineageWithout(t, backfill3File), lateSteps); err != nil {
		t.Fatalf("run 196: %v", err)
	}
	meta := ledgertest.Meta(t, database)
	if meta[migplan.StepKey(196)] != migplan.RecordApplied || meta["version"] != strconv.Itoa(LatestSchemaVersion()) {
		t.Fatalf("after the upgrade: migration:196=%q version=%q, want applied at the head %d", meta[migplan.StepKey(196)], meta["version"], LatestSchemaVersion())
	}
	after := taxBackfillSnapshot(ctx, t, database)
	for _, c := range backfill2Cases {
		pre := after["pre|"+c.tool+"|"+c.raw]
		post := after["post|"+c.tool+"|"+c.raw]
		if c.want != "" && pre != c.want {
			t.Errorf("after 196: %s %s = %q, want %q", c.tool, c.raw, pre, c.want)
		}
		if c.want == "" && pre == "unknown" {
			t.Errorf("after 196: %s %s is still unknown; the newer table names it", c.tool, c.raw)
		}
		if pre != post {
			t.Errorf("%s %s: a row that ran 077 then 196 is %q but one that ran only 196 is %q", c.tool, c.raw, pre, post)
		}
		if got := after["classified|"+c.tool+"|"+c.raw]; got != "post_tool_batch" {
			t.Errorf("CONTROL %s %s: an adapter-classified row moved to %q", c.tool, c.raw, got)
		}
	}

	for _, c := range backfill3Cases {
		if got := after["pre|"+c.tool+"|"+c.raw]; got != "unknown" {
			t.Errorf("after 196: %s %s = %q, want unknown (only 223 names it)", c.tool, c.raw, got)
		}
		// Rows ingested after 196 ran, still unknown.
		seed("post196", "unknown", c)
	}

	// The upgrade that carries 223: the runner applies exactly 223, which
	// classifies only what 196 could not and leaves every other row alone.
	if err := runMigrationsFrom(ctx, database, defaultMigrationLockWait, migrations.Files, lateSteps); err != nil {
		t.Fatalf("run 223: %v", err)
	}
	meta = ledgertest.Meta(t, database)
	if meta[migplan.StepKey(223)] != migplan.RecordApplied || meta["version"] != strconv.Itoa(LatestSchemaVersion()) {
		t.Fatalf("after the 223 upgrade: migration:223=%q version=%q, want applied at the head %d", meta[migplan.StepKey(223)], meta["version"], LatestSchemaVersion())
	}
	after223 := taxBackfillSnapshot(ctx, t, database)
	for id, want := range after {
		if strings.HasPrefix(id, "pre|cursor|") || strings.HasPrefix(id, "post196|") {
			continue
		}
		if after223[id] != want {
			t.Errorf("223 moved %s from %q to %q; it may only move the rows 196 left unknown", id, want, after223[id])
		}
	}
	for _, c := range backfill3Cases {
		for _, phase := range []string{"pre", "post196"} {
			if got := after223[phase+"|"+c.tool+"|"+c.raw]; got != c.want {
				t.Errorf("after 223: %s %s %s = %q, want %q", phase, c.tool, c.raw, got, c.want)
			}
		}
		if got := after223["classified|"+c.tool+"|"+c.raw]; got != "post_tool_batch" {
			t.Errorf("CONTROL %s %s: an adapter-classified row moved to %q", c.tool, c.raw, got)
		}
	}
	after = after223

	// Re-running any body changes nothing.
	for _, v := range []int{223, 196, 77} {
		if _, err := database.ExecContext(ctx, bodies[v]); err != nil {
			t.Fatalf("re-run %d: %v", v, err)
		}
		again := taxBackfillSnapshot(ctx, t, database)
		for id, want := range after {
			if again[id] != want {
				t.Errorf("re-running %d moved %s from %q to %q", v, id, want, again[id])
			}
		}
	}
}

// TestNodeRunnerRunsReservedStepsAfterAHigherOne pins the D-880 hand-over
// between the two lines: integ ships node 196 while the plans line still
// holds 177-195. A database that ran 196 first must run 177-195 when they
// arrive (T-979 per-step ledger), in ascending order, without re-running
// anything and with the version record staying at 196.
func TestNodeRunnerRunsReservedStepsAfterAHigherOne(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	step := func(v int) string {
		if v == 176 {
			return `CREATE TABLE run_order (seq INTEGER PRIMARY KEY AUTOINCREMENT, step INTEGER NOT NULL);
INSERT INTO run_order (step) VALUES (176);`
		}
		return fmt.Sprintf("CREATE TABLE t%d (x INTEGER); INSERT INTO run_order (step) VALUES (%d);", v, v)
	}
	lineage := func(versions ...int) fstest.MapFS {
		m := fstest.MapFS{}
		for _, v := range versions {
			m[fmt.Sprintf("%03d_step.sql", v)] = &fstest.MapFile{Data: []byte(step(v))}
		}
		return m
	}
	integ := []int{176, 196}
	merged := []int{176}
	for v := 177; v <= 195; v++ {
		merged = append(merged, v)
	}
	merged = append(merged, 196)

	d := ledgertest.OpenRaw(t)
	if err := runMigrationsFrom(ctx, d, defaultMigrationLockWait, lineage(integ...), nil); err != nil {
		t.Fatalf("integ run: %v", err)
	}
	if err := runMigrationsFrom(ctx, d, defaultMigrationLockWait, lineage(merged...), nil); err != nil {
		t.Fatalf("merged run: %v", err)
	}
	rows, err := d.QueryContext(ctx, `SELECT step FROM run_order ORDER BY seq`)
	if err != nil {
		t.Fatalf("run_order: %v", err)
	}
	defer rows.Close()
	var got []int
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		got = append(got, v)
	}
	want := append([]int{176, 196}, merged[1:len(merged)-1]...)
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("run order = %v, want %v (each step once; 177-195 after 196, ascending)", got, want)
	}
	meta := ledgertest.Meta(t, d)
	if meta["version"] != "196" {
		t.Fatalf("version = %q, want 196", meta["version"])
	}
	for _, v := range merged {
		if meta[migplan.StepKey(v)] != migplan.RecordApplied {
			t.Errorf("migration:%d = %q, want applied", v, meta[migplan.StepKey(v)])
		}
	}
}
