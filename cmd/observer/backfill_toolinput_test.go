package main

// Tests for --codex-tool-input, over a TEMP fixture DB built from the
// real migrations plus real (small) codex rollout files on disk. The
// pass has no pure planner to test in isolation — its whole risk surface
// is the seam where a DB row meets a source record — so every case runs
// end-to-end and asserts on the DB afterwards.
//
// MUTATION PROOF MAP — the two highest-risk behaviours, the exact
// implementation line each test kills, and the mutant run against it
// (results in the session report):
//
//	never-overwrite, work layer  → the emptiness predicate in
//	    loadToolInputCandidates. Killed by
//	    TestBackfillToolInputNeverOverwrites.
//	never-overwrite, value layer → the same predicate in
//	    toolInputUpdateSQL. This one SURVIVED the end-to-end test (the
//	    candidate SELECT filters populated rows out before any write is
//	    planned), so it is asserted where it is reachable — at the
//	    statement — by TestToolInputUpdateSQLRefusesPopulatedRow. The
//	    end-to-end test was NOT widened to chase it; isolating the two
//	    layers showed this clause is the one that protects the stored
//	    value, and the SELECT predicate only avoids pointless work.
//	never-invent → the `case spec.Expect == inputNeverExists` branch in
//	    backfillToolInput's partition, the `!known` fail-closed branch
//	    beside it, the derived-empty check in the per-row loop, and the
//	    empty-value guard in scrubbedChanges. Killed by
//	    TestBackfillToolInputNeverInvents,
//	    TestScrubbedChangesNeverInvents and
//	    TestBackfillToolInputEmptyChangesStaysUnresolved.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// toolInputFixtureRow describes one seeded actions row.
type toolInputFixtureRow struct {
	id         int64
	tool       string
	actionType string
	rawName    string
	// sourceFile is written verbatim; "" seeds a NULL.
	sourceFile string
	// eventID becomes source_event_id — the join key.
	eventID string
	// input seeds raw_tool_input; "" seeds a NULL (the empty case).
	input string
}

// rolloutLines is the minimal codex rollout this suite writes to disk:
// a session_meta, then whatever event records the case needs.
func rolloutLines(records ...string) string {
	head := `{"timestamp":"2026-07-31T10:00:00.000Z","type":"session_meta","payload":{"id":"sess-1","timestamp":"2026-07-31T10:00:00.000Z","cwd":"/tmp/ti-fixture","originator":"codex_cli_rs","cli_version":"0.50.0"}}`
	return head + "\n" + strings.Join(records, "\n") + "\n"
}

// patchApplyEndRecord renders a real patch_apply_end event_msg with the
// `changes` shape live codex writes (path → {type, unified_diff}).
func patchApplyEndRecord(callID, path, diff string) string {
	changes := map[string]any{
		path: map[string]any{"type": "update", "unified_diff": diff, "move_path": nil},
	}
	b, _ := json.Marshal(changes)
	return fmt.Sprintf(
		`{"timestamp":"2026-07-31T10:00:01.000Z","type":"event_msg","payload":{"type":"patch_apply_end","call_id":%q,"turn_id":"turn-1","stdout":"Success.","stderr":"","success":true,"changes":%s,"status":"completed"}}`,
		callID, string(b),
	)
}

// patchApplyEndRaw renders a patch_apply_end whose `changes` is whatever
// the caller supplies verbatim — used for the null / {} / absent cases.
func patchApplyEndRaw(callID, changesJSON string) string {
	return fmt.Sprintf(
		`{"timestamp":"2026-07-31T10:00:01.000Z","type":"event_msg","payload":{"type":"patch_apply_end","call_id":%q,"turn_id":"turn-1","stdout":"","stderr":"","success":true,"changes":%s,"status":"completed"}}`,
		callID, changesJSON,
	)
}

// seedToolInputFixture builds a temp DB on the real migrations and seeds
// one project, one session and the caller's rows.
func seedToolInputFixture(t *testing.T, ctx context.Context, rows []toolInputFixtureRow) *sql.DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "obs.db")
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })

	if _, err := database.ExecContext(ctx,
		`INSERT INTO projects (id, root_path, created_at) VALUES (1, '/tmp/ti-fixture', '2026-07-31T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, tool, started_at, project_id) VALUES ('sess-1', 'codex', '2026-07-31T00:00:00Z', 1)`); err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if _, err := database.ExecContext(ctx,
			`INSERT INTO actions (id, session_id, project_id, timestamp, action_type, tool,
			                      raw_tool_name, source_file, source_event_id, raw_tool_input)
			 VALUES (?, 'sess-1', 1, '2026-07-31T10:00:01Z', ?, ?, ?, ?, ?, ?)`,
			r.id, r.actionType, r.tool, nullIfEmpty(r.rawName),
			nullIfEmpty(r.sourceFile), nullIfEmpty(r.eventID), nullIfEmpty(r.input)); err != nil {
			t.Fatal(err)
		}
	}
	return database
}

// inputOf reads back one row's raw_tool_input.
func inputOf(t *testing.T, ctx context.Context, database *sql.DB, id int64) string {
	t.Helper()
	var v sql.NullString
	if err := database.QueryRowContext(ctx, `SELECT raw_tool_input FROM actions WHERE id = ?`, id).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v.String
}

// writeToolInputRollout drops a rollout file into a temp dir and returns its path.
func writeToolInputRollout(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "rollout-2026-07-31T10-00-00-sess-1.jsonl")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestBackfillToolInputHappyPath: an edit_file row whose source
// patch_apply_end still holds its `changes` map is re-derived from it,
// joined on call_id, and the dry run writes nothing.
func TestBackfillToolInputHappyPath(t *testing.T) {
	ctx := context.Background()
	const callID = "exec-11111111-1111-4111-8111-111111111111"
	const diff = "@@ -1,2 +1,2 @@\n def add(a, b):\n-    return a - b\n+    return a + b\n"
	path := writeToolInputRollout(t, rolloutLines(patchApplyEndRecord(callID, "/tmp/ti-fixture/calc.py", diff)))

	database := seedToolInputFixture(t, ctx, []toolInputFixtureRow{
		{id: 1, tool: models.ToolCodex, actionType: models.ActionEditFile, rawName: "patch_apply_end", sourceFile: path, eventID: callID},
	})

	dry, err := backfillToolInput(ctx, database, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if dry.Updated != 1 || dry.Examined != 1 {
		t.Fatalf("dry run: examined=%d updated=%d, want 1/1 (%+v)", dry.Examined, dry.Updated, dry)
	}
	if got := inputOf(t, ctx, database, 1); got != "" {
		t.Fatalf("dry run mutated the row: %q", got)
	}

	got, err := backfillToolInput(ctx, database, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Updated != 1 {
		t.Fatalf("apply: updated=%d, want 1 (%+v)", got.Updated, got)
	}
	stored := inputOf(t, ctx, database, 1)
	if stored == "" {
		t.Fatal("apply wrote nothing")
	}
	// The value must be the source record's own bytes, not a summary:
	// the unified diff has to survive into the column.
	if !strings.Contains(stored, "return a + b") || !strings.Contains(stored, "/tmp/ti-fixture/calc.py") {
		t.Fatalf("stored input lost the source payload: %q", stored)
	}
	var probe map[string]any
	if err := json.Unmarshal([]byte(stored), &probe); err != nil {
		t.Fatalf("stored input is not valid JSON (%v): %q", err, stored)
	}
}

// TestBackfillToolInputNeverOverwrites: a row that already carries an
// input is never selected, never counted as examined, and is byte-for-
// byte unchanged after --apply — even though its source record holds a
// DIFFERENT value that a broken pass would happily write over it.
//
// MUTATION PROOF (a). Kills the never-overwrite guard.
func TestBackfillToolInputNeverOverwrites(t *testing.T) {
	ctx := context.Background()
	const callID = "exec-22222222-2222-4222-8222-222222222222"
	const existing = `{"already":"here — the operator's own value"}`
	path := writeToolInputRollout(t, rolloutLines(
		patchApplyEndRecord(callID, "/tmp/ti-fixture/other.py", "@@ -1 +1 @@\n-old\n+new\n"),
	))

	database := seedToolInputFixture(t, ctx, []toolInputFixtureRow{
		{id: 1, tool: models.ToolCodex, actionType: models.ActionEditFile, rawName: "patch_apply_end", sourceFile: path, eventID: callID, input: existing},
	})

	res, err := backfillToolInput(ctx, database, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Updated != 0 {
		t.Fatalf("updated=%d, want 0 — a populated row was rewritten", res.Updated)
	}
	if res.Examined != 0 {
		t.Fatalf("examined=%d, want 0 — a populated row was selected as a candidate", res.Examined)
	}
	if res.AlreadyPopulated != 1 {
		t.Fatalf("already_populated=%d, want 1", res.AlreadyPopulated)
	}
	if got := inputOf(t, ctx, database, 1); got != existing {
		t.Fatalf("populated row was overwritten:\n got %q\nwant %q", got, existing)
	}
}

// TestBackfillToolInputNeverInvents pins the never-invent guard across
// all four ways a row can fail to ground: an action type that
// legitimately has no input, a (tool, action_type) pair the grounding
// table does not name, a source file that is gone, and a source record
// that is absent from a file that IS present.
//
// Every one of these rows sits in a fixture where a REAL, recoverable
// value exists elsewhere in the same file — so a pass that reaches for
// "any input in this file" writes something and fails.
//
// MUTATION PROOF (b). Kills the no-input / fail-closed branches.
func TestBackfillToolInputNeverInvents(t *testing.T) {
	ctx := context.Background()
	const realCall = "exec-33333333-3333-4333-8333-333333333333"
	path := writeToolInputRollout(t, rolloutLines(
		patchApplyEndRecord(realCall, "/tmp/ti-fixture/real.py", "@@ -1 +1 @@\n-a\n+b\n"),
	))
	gone := filepath.Join(t.TempDir(), "rollout-2026-07-31T10-00-00-vanished.jsonl")

	tests := []struct {
		name string
		row  toolInputFixtureRow
		// wantBucket names the counter the row must land in.
		wantBucket func(ToolInputBackfill) int
		bucketName string
	}{
		{
			name: "assistant_message legitimately has no input",
			row: toolInputFixtureRow{
				id: 10, tool: models.ToolCodex, actionType: models.ActionAssistantMessage,
				rawName: "codex.assistant_text", sourceFile: path, eventID: realCall,
			},
			wantBucket: func(r ToolInputBackfill) int { return r.SkippedNoInputForActionType },
			bucketName: "skipped_no_input_for_action_type",
		},
		{
			name: "task_complete legitimately has no input",
			row: toolInputFixtureRow{
				id: 11, tool: models.ToolCodex, actionType: models.ActionTaskComplete,
				rawName: "task_complete", sourceFile: path, eventID: realCall,
			},
			wantBucket: func(r ToolInputBackfill) int { return r.SkippedNoInputForActionType },
			bucketName: "skipped_no_input_for_action_type",
		},
		{
			name: "turn_aborted legitimately has no input",
			row: toolInputFixtureRow{
				id: 12, tool: models.ToolCodex, actionType: models.ActionTurnAborted,
				rawName: "turn_aborted", sourceFile: path, eventID: realCall,
			},
			wantBucket: func(r ToolInputBackfill) int { return r.SkippedNoInputForActionType },
			bucketName: "skipped_no_input_for_action_type",
		},
		{
			name: "session_start comes from the hook, not a rollout",
			row: toolInputFixtureRow{
				id: 13, tool: models.ToolCodex, actionType: models.ActionSessionStart,
				sourceFile: "codex:hook", eventID: "sess-1:session_start",
			},
			wantBucket: func(r ToolInputBackfill) int { return r.SkippedNoInputForActionType },
			bucketName: "skipped_no_input_for_action_type",
		},
		{
			name: "unnamed (tool, action_type) pair fails closed",
			row: toolInputFixtureRow{
				id: 14, tool: models.ToolCodex, actionType: models.ActionRunCommand,
				rawName: "exec_command_end", sourceFile: path, eventID: realCall,
			},
			wantBucket: func(r ToolInputBackfill) int { return r.SkippedUnclassified },
			bucketName: "skipped_unclassified",
		},
		{
			name: "source file no longer on disk",
			row: toolInputFixtureRow{
				id: 15, tool: models.ToolCodex, actionType: models.ActionEditFile,
				rawName: "patch_apply_end", sourceFile: gone, eventID: realCall,
			},
			wantBucket: func(r ToolInputBackfill) int { return r.UnresolvedFileMissing },
			bucketName: "unresolved_source_file_missing",
		},
		{
			name: "source record absent from a file that is present",
			row: toolInputFixtureRow{
				id: 16, tool: models.ToolCodex, actionType: models.ActionEditFile,
				rawName: "patch_apply_end", sourceFile: path,
				eventID: "exec-99999999-9999-4999-8999-999999999999",
			},
			wantBucket: func(r ToolInputBackfill) int { return r.UnresolvedNoSourceRecord },
			bucketName: "unresolved_source_record_absent",
		},
		{
			name: "synthesized line-number key is not joined",
			row: toolInputFixtureRow{
				id: 17, tool: models.ToolCodex, actionType: models.ActionEditFile,
				rawName: "patch_apply_end", sourceFile: path,
				eventID: "patch:rollout-2026-07-31T10-00-00-sess-1.jsonl:L2",
			},
			wantBucket: func(r ToolInputBackfill) int { return r.UnresolvedNoSourceRecord },
			bucketName: "unresolved_source_record_absent",
		},
		// DECOY, placed last on purpose: the one row that MUST be
		// written. A mutant that silences every branch above by
		// refusing to write at all still has to satisfy this row.
		{
			name: "decoy — a genuinely recoverable edit_file IS written",
			row: toolInputFixtureRow{
				id: 18, tool: models.ToolCodex, actionType: models.ActionEditFile,
				rawName: "patch_apply_end", sourceFile: path, eventID: realCall,
			},
			wantBucket: func(r ToolInputBackfill) int { return r.Updated },
			bucketName: "updated",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			database := seedToolInputFixture(t, ctx, []toolInputFixtureRow{tc.row})
			res, err := backfillToolInput(ctx, database, true, nil)
			if err != nil {
				t.Fatal(err)
			}
			if res.Examined != 1 {
				t.Fatalf("examined=%d, want 1", res.Examined)
			}
			if got := tc.wantBucket(res); got != 1 {
				t.Fatalf("bucket %s = %d, want 1 (%+v)", tc.bucketName, got, res)
			}
			stored := inputOf(t, ctx, database, tc.row.id)
			if tc.bucketName == "updated" {
				if stored == "" {
					t.Fatal("the recoverable row was not written — the pass writes nothing at all")
				}
				return
			}
			if stored != "" {
				t.Fatalf("a value was INVENTED for a row with no grounded input: %q", stored)
			}
		})
	}
}

// TestToolInputUpdateSQLRefusesPopulatedRow asserts the never-overwrite
// guard at the seam that actually owns it: the UPDATE statement.
//
// MUTATION PROOF (a), value layer — and the reason this test exists as a
// separate case. Mutating the guard OFF the UPDATE alone SURVIVED
// TestBackfillToolInputNeverOverwrites, because the candidate SELECT
// filters populated rows out before any write is planned. That survival
// was data, not a gap to paper over by widening the end-to-end test:
// isolating the layers showed the UPDATE clause is the guard that
// protects the stored VALUE (SELECT guard mutated away + UPDATE guard
// intact → value survives; both away → value clobbered). So the
// assertion belongs here, bound to the shipped statement, where the
// mutant is reachable.
func TestToolInputUpdateSQLRefusesPopulatedRow(t *testing.T) {
	ctx := context.Background()
	const existing = `{"already":"here"}`
	database := seedToolInputFixture(t, ctx, []toolInputFixtureRow{
		{id: 1, tool: models.ToolCodex, actionType: models.ActionEditFile, rawName: "patch_apply_end", sourceFile: "/tmp/x.jsonl", eventID: "exec-1", input: existing},
		{id: 2, tool: models.ToolCodex, actionType: models.ActionEditFile, rawName: "patch_apply_end", sourceFile: "/tmp/x.jsonl", eventID: "exec-2"},
	})

	// Populated row: the statement must match nothing.
	got, err := database.ExecContext(ctx, toolInputUpdateSQL, "REWRITTEN", 1)
	if err != nil {
		t.Fatal(err)
	}
	n, err := got.RowsAffected()
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("rows affected = %d, want 0 — the statement rewrote a populated row", n)
	}
	if v := inputOf(t, ctx, database, 1); v != existing {
		t.Fatalf("populated row changed:\n got %q\nwant %q", v, existing)
	}

	// DECOY, last: the same statement MUST still write an empty row, so
	// a mutant that neuters the UPDATE entirely cannot pass.
	got, err = database.ExecContext(ctx, toolInputUpdateSQL, "WRITTEN", 2)
	if err != nil {
		t.Fatal(err)
	}
	if n, _ = got.RowsAffected(); n != 1 {
		t.Fatalf("rows affected = %d, want 1 — the statement no longer writes empty rows", n)
	}
	if v := inputOf(t, ctx, database, 2); v != "WRITTEN" {
		t.Fatalf("empty row not written: %q", v)
	}
}

// TestBackfillToolInputIdempotent: a second --apply over an
// already-converged DB selects nothing and changes nothing.
func TestBackfillToolInputIdempotent(t *testing.T) {
	ctx := context.Background()
	const callID = "exec-44444444-4444-4444-8444-444444444444"
	path := writeToolInputRollout(t, rolloutLines(
		patchApplyEndRecord(callID, "/tmp/ti-fixture/idem.py", "@@ -1 +1 @@\n-x\n+y\n"),
	))
	database := seedToolInputFixture(t, ctx, []toolInputFixtureRow{
		{id: 1, tool: models.ToolCodex, actionType: models.ActionEditFile, rawName: "patch_apply_end", sourceFile: path, eventID: callID},
	})

	first, err := backfillToolInput(ctx, database, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if first.Updated != 1 {
		t.Fatalf("first run updated=%d, want 1", first.Updated)
	}
	afterFirst := inputOf(t, ctx, database, 1)

	second, err := backfillToolInput(ctx, database, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if second.Updated != 0 || second.Examined != 0 {
		t.Fatalf("re-run not idempotent: examined=%d updated=%d (%+v)", second.Examined, second.Updated, second)
	}
	if got := inputOf(t, ctx, database, 1); got != afterFirst {
		t.Fatalf("re-run changed the value:\n got %q\nwant %q", got, afterFirst)
	}
}

// TestScrubbedChangesNeverInvents pins the value-level half of the
// never-invent rule: a patch_apply_end that recorded no changes yields
// nothing, so its row stays unresolved rather than gaining "{}" or
// "null" as a "value".
//
// MUTATION PROOF (b), value layer.
func TestScrubbedChangesNeverInvents(t *testing.T) {
	sc := scrub.New()
	tests := []struct {
		name string
		raw  string
		want bool // true = must yield a value
	}{
		{"absent changes field", "", false},
		{"json null", "null", false},
		{"empty object", "{}", false},
		{"whitespace-padded empty object", "  {}  ", false},
		{"malformed json", `{"a":`, false},
		{"non-object", `"a string"`, false},
		// DECOY last: a real changes map MUST yield its bytes.
		{"real changes map", `{"/p.py":{"type":"update","unified_diff":"@@\n-a\n+b\n"}}`, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := scrubbedChanges(sc, json.RawMessage(tc.raw))
			if (got != "") != tc.want {
				t.Fatalf("scrubbedChanges(%q) = %q, want value=%v", tc.raw, got, tc.want)
			}
		})
	}
}

// TestBackfillToolInputEmptyChangesStaysUnresolved runs the empty-changes
// shapes through the full DB path, so the guard is proven where it
// matters and not only in the helper.
func TestBackfillToolInputEmptyChangesStaysUnresolved(t *testing.T) {
	ctx := context.Background()
	for _, changes := range []string{"null", "{}"} {
		t.Run("changes="+changes, func(t *testing.T) {
			const callID = "exec-55555555-5555-4555-8555-555555555555"
			path := writeToolInputRollout(t, rolloutLines(patchApplyEndRaw(callID, changes)))
			database := seedToolInputFixture(t, ctx, []toolInputFixtureRow{
				{id: 1, tool: models.ToolCodex, actionType: models.ActionEditFile, rawName: "patch_apply_end", sourceFile: path, eventID: callID},
			})
			res, err := backfillToolInput(ctx, database, true, nil)
			if err != nil {
				t.Fatal(err)
			}
			if res.Updated != 0 || res.UnresolvedNoSourceRecord != 1 {
				t.Fatalf("updated=%d unresolved=%d, want 0/1 (%+v)", res.Updated, res.UnresolvedNoSourceRecord, res)
			}
			if got := inputOf(t, ctx, database, 1); got != "" {
				t.Fatalf("an empty changes map produced a value: %q", got)
			}
		})
	}
}

// TestToolInputGroundingTableIsExact guards the table's own shape: no
// duplicate (tool, action_type) pair (which would make groundingFor's
// first-match arbitrary), and every verdict named.
func TestToolInputGroundingTableIsExact(t *testing.T) {
	seen := map[string]string{}
	for _, s := range toolInputSpecs {
		key := s.Tool + "\x00" + s.ActionType
		if prev, dup := seen[key]; dup {
			t.Fatalf("duplicate grounding row for (%s, %s): %q and %q", s.Tool, s.ActionType, prev, s.Site)
		}
		seen[key] = s.Site
		if s.Expect != inputRecoverable && s.Expect != inputNeverExists {
			t.Fatalf("(%s, %s) has an unnamed verdict %q", s.Tool, s.ActionType, s.Expect)
		}
		if s.Site == "" {
			t.Fatalf("(%s, %s) carries no grounding site", s.Tool, s.ActionType)
		}
	}
	if _, ok := groundingFor(models.ToolCodex, "a_type_that_does_not_exist"); ok {
		t.Fatal("groundingFor matched a pair the table does not name")
	}
}

// TestBackfillToolInputReportNamesTheNoInputBucket pins the report
// surface: the legitimately-input-free count must be visible as its own
// line, not folded into a total.
func TestBackfillToolInputReportNamesTheNoInputBucket(t *testing.T) {
	ctx := context.Background()
	path := writeToolInputRollout(t, rolloutLines())
	database := seedToolInputFixture(t, ctx, []toolInputFixtureRow{
		{id: 1, tool: models.ToolCodex, actionType: models.ActionAssistantMessage, rawName: "codex.assistant_text", sourceFile: path, eventID: "agent:x:L2:deadbeef"},
	})
	var sb strings.Builder
	if _, err := backfillToolInput(ctx, database, false, &sb); err != nil {
		t.Fatal(err)
	}
	out := sb.String()
	if !strings.Contains(out, "legitimately has no input: 1") {
		t.Fatalf("report does not name the no-input bucket:\n%s", out)
	}
	if !strings.Contains(out, models.ActionAssistantMessage) {
		t.Fatalf("report has no per-action_type line:\n%s", out)
	}
}
