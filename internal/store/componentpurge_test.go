package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// seedMixedAdapters seeds two adapters' rows: zed (the purge target) and
// claude-code (must survive untouched), plus one shared session that holds
// rows from both, and turns the org-push floors on so an unmarked delete
// WOULD emit a tombstone.
func seedMixedAdapters(t *testing.T, s *Store) {
	t.Helper()
	ctx := context.Background()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := s.db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("seed %q: %v", q, err)
		}
	}
	for _, k := range []string{"sessions", "actions", "token_usage", "api_turns"} {
		exec(`INSERT INTO schema_meta (key, value) VALUES (?, '0') ON CONFLICT(key) DO UPDATE SET value = '0'`, "org_push_floor_"+k)
	}
	exec(`INSERT INTO projects (id, root_path, created_at) VALUES (1, '/tmp/p', '2026-10-07T00:00:00Z')`)
	sessions := []struct{ id, tool string }{
		{"z1", "zed"}, {"z2", "zed"}, {"c1", "claude-code"}, {"mixed", "zed"},
	}
	for _, se := range sessions {
		exec(`INSERT INTO sessions (id, project_id, tool, started_at) VALUES (?, 1, ?, '2026-10-07T00:00:00Z')`, se.id, se.tool)
	}
	act := func(session, tool string, n int) {
		for i := 0; i < n; i++ {
			exec(`INSERT INTO actions (session_id, project_id, timestamp, action_type, tool, success, target, source_file, source_event_id)
				VALUES (?, 1, '2026-10-07T00:00:01Z', 'read_file', ?, 1, 't', 'f', ?)`, session, tool, fmt.Sprintf("%s-%s-%d", session, tool, i))
		}
	}
	tok := func(session, tool string) {
		exec(`INSERT INTO token_usage (session_id, timestamp, tool, model, input_tokens, output_tokens, source, reliability, source_file, source_event_id)
			VALUES (?, '2026-10-07T00:00:02Z', ?, 'm', 1, 1, 'jsonl', 'estimated', 'f', ?)`, session, tool, session+"-"+tool)
	}
	act("z1", "zed", 3)
	act("z2", "zed", 2)
	act("c1", "claude-code", 4)
	act("mixed", "zed", 1)
	act("mixed", "claude-code", 1) // another source in the zed session: keep it
	tok("z1", "zed")
	tok("c1", "claude-code")
	// Excerpts and a failure_context row hang off a zed action.
	var zedAction int64
	if err := s.db.QueryRowContext(ctx, `SELECT id FROM actions WHERE session_id = 'z1' ORDER BY id LIMIT 1`).Scan(&zedAction); err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO action_excerpts (action_id, tool_name, target, excerpt, error_message) VALUES (?, 'read_file', 't', 'x', '')`, zedAction)
	exec(`INSERT INTO failure_context (action_id, session_id, project_id, timestamp, command_hash, command_summary) VALUES (?, 'z1', 1, '2026-10-07T00:00:03Z', 'h', 's')`, zedAction)
}

func purgeCount(t *testing.T, db *sql.DB, q string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatalf("count %q: %v", q, err)
	}
	return n
}

func TestNextPurgeStateTable(t *testing.T) {
	cases := []struct {
		kind  PurgeKind
		from  PurgeState
		event PurgeEvent
		to    PurgeState
		ok    bool
	}{
		{PurgeInteractive, PurgePreviewed, PurgeEventExecute, PurgeConsumed, true},
		{PurgeInteractive, PurgePreviewed, PurgeEventExpire, PurgeExpired, true},
		{PurgeInteractive, PurgePreviewed, PurgeEventCancel, PurgeCancelled, true},
		{PurgeInteractive, PurgePreviewed, PurgeEventGraceElapsed, "", false},
		{PurgeInteractive, PurgeConsumed, PurgeEventExecute, "", false},
		{PurgeScheduled, PurgeGracePending, PurgeEventExecute, "", false},
		{PurgeScheduled, PurgeGracePending, PurgeEventGraceElapsed, PurgeEligible, true},
		{PurgeScheduled, PurgeGracePending, PurgeEventCancel, PurgeCancelled, true},
		{PurgeScheduled, PurgeGracePending, PurgeEventExpire, PurgeExpired, true},
		{PurgeScheduled, PurgeEligible, PurgeEventExecute, PurgeConsumed, true},
		{PurgeScheduled, PurgeEligible, PurgeEventCancel, PurgeCancelled, true},
		{PurgeScheduled, PurgeEligible, PurgeEventExpire, PurgeExpired, true},
		{PurgeScheduled, PurgeExpired, PurgeEventExecute, "", false},
		{PurgeScheduled, PurgeCancelled, PurgeEventExecute, "", false},
	}
	for _, tc := range cases {
		got, ok := NextPurgeState(tc.kind, tc.from, tc.event)
		if ok != tc.ok || got != tc.to {
			t.Errorf("%s %s --%s--> got (%s,%v) want (%s,%v)", tc.kind, tc.from, tc.event, got, ok, tc.to, tc.ok)
		}
	}
}

func TestAdapterPurgeDeletesOnlyThatSourceAndNoTombstone(t *testing.T) {
	s, database := newTestStore(t)
	ctx := context.Background()
	seedMixedAdapters(t, s)
	tombsBefore := purgeCount(t, database, `SELECT COUNT(*) FROM org_push_deletions`)

	plan, err := s.CreateComponentPurgePlan(ctx, ComponentPurgeSpec{Kind: PurgeInteractive, Component: "adapter.zed", CatalogVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Counts["actions"] != 6 || plan.Counts["token_usage"] != 1 || plan.Counts["sessions"] != 3 {
		t.Fatalf("candidate counts: %v", plan.Counts)
	}

	// Between preview and confirmation: one zed action is retagged (no
	// longer matches), one new zed action arrives (not in the plan).
	if _, err := database.Exec(`UPDATE actions SET tool = 'claude-code' WHERE session_id = 'z2' AND source_event_id = 'z2-zed-0'`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO actions (session_id, project_id, timestamp, action_type, tool, success, target, source_file, source_event_id)
		VALUES ('z2', 1, '2026-10-07T00:00:09Z', 'read_file', 'zed', 1, 't', 'f', 'late')`); err != nil {
		t.Fatal(err)
	}

	res, err := s.ExecuteComponentPurgePlan(ctx, plan.ID, nil, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Deleted["actions"] != 5 || res.Skipped["actions"] != 1 {
		t.Fatalf("actions result: %+v", res)
	}
	if got := purgeCount(t, database, `SELECT COUNT(*) FROM actions WHERE tool = 'claude-code'`); got != 6 {
		t.Fatalf("claude-code actions changed: %d (want 4 seeded + 1 mixed + 1 retagged)", got)
	}
	if got := purgeCount(t, database, `SELECT COUNT(*) FROM actions WHERE source_event_id = 'late'`); got != 1 {
		t.Fatal("an action that arrived after the preview was deleted")
	}
	if got := purgeCount(t, database, `SELECT COUNT(*) FROM token_usage WHERE tool = 'zed'`); got != 0 {
		t.Fatalf("zed token rows left: %d", got)
	}
	if got := purgeCount(t, database, `SELECT COUNT(*) FROM token_usage WHERE tool = 'claude-code'`); got != 1 {
		t.Fatal("claude-code token row touched")
	}
	// z1 had only zed rows: deleted. z2 still holds the retagged and the
	// late action; mixed holds a claude-code action: both kept.
	if got := purgeCount(t, database, `SELECT COUNT(*) FROM sessions WHERE id = 'z1'`); got != 0 {
		t.Fatal("z1 kept")
	}
	if got := purgeCount(t, database, `SELECT COUNT(*) FROM sessions WHERE id IN ('z2', 'mixed', 'c1')`); got != 3 {
		t.Fatal("a session with another source's rows was deleted")
	}
	if res.KeptSessions != 2 {
		t.Fatalf("kept sessions: %d", res.KeptSessions)
	}
	if got := purgeCount(t, database, `SELECT COUNT(*) FROM action_excerpts`); got != 0 {
		t.Fatal("a searchable excerpt ghost survived")
	}
	if got := purgeCount(t, database, `SELECT COUNT(*) FROM failure_context`); got != 0 {
		t.Fatal("failure_context row survived")
	}
	if got := purgeCount(t, database, `SELECT COUNT(*) FROM org_push_deletions`); got != tombsBefore {
		t.Fatalf("purge emitted %d org tombstones", got-tombsBefore)
	}
	// The trigger is live: an unmarked delete WOULD tombstone.
	if _, err := database.Exec(`DELETE FROM actions WHERE source_event_id = 'late'`); err != nil {
		t.Fatal(err)
	}
	if got := purgeCount(t, database, `SELECT COUNT(*) FROM org_push_deletions`); got != tombsBefore+1 {
		t.Fatal("control: an unmarked delete did not tombstone, so the test proves nothing")
	}

	// One-shot.
	if _, err := s.ExecuteComponentPurgePlan(ctx, plan.ID, nil, time.Time{}); !errors.Is(err, ErrPurgePlanNotExecutable) {
		t.Fatalf("second execute: %v", err)
	}
	got, err := s.ComponentPurgePlanByID(ctx, plan.ID)
	if err != nil || got.State != PurgeConsumed || got.Result == nil || got.Result.Deleted["actions"] != 5 {
		t.Fatalf("consumed plan: %+v %v", got, err)
	}
	if n := purgeCount(t, database, `SELECT COUNT(*) FROM component_purge_candidates WHERE plan_id = ?`, plan.ID); n != 0 {
		t.Fatal("candidates not cleared after consumption")
	}
}

func TestInteractivePurgeExpires(t *testing.T) {
	s, database := newTestStore(t)
	ctx := context.Background()
	seedMixedAdapters(t, s)
	t0 := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	plan, err := s.CreateComponentPurgePlan(ctx, ComponentPurgeSpec{Kind: PurgeInteractive, Component: "adapter.zed", Now: t0})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ExecuteComponentPurgePlan(ctx, plan.ID, nil, t0.Add(InteractivePurgeTTL+time.Second)); !errors.Is(err, ErrPurgePlanNotExecutable) {
		t.Fatalf("expired execute: %v", err)
	}
	if got := purgeCount(t, database, `SELECT COUNT(*) FROM actions WHERE tool = 'zed'`); got != 6 {
		t.Fatal("an expired plan deleted rows")
	}
	p, _ := s.ComponentPurgePlanByID(ctx, plan.ID)
	if p.State != PurgeExpired {
		t.Fatalf("state %s", p.State)
	}
}

func TestScheduledPurgeGraceRecheckAndCancel(t *testing.T) {
	s, database := newTestStore(t)
	ctx := context.Background()
	seedMixedAdapters(t, s)
	t0 := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	plan, err := s.CreateComponentPurgePlan(ctx, ComponentPurgeSpec{Kind: PurgeScheduled, Component: "adapter.zed", PolicyVersion: "v3", Grace: time.Hour, Now: t0})
	if err != nil {
		t.Fatal(err)
	}
	allow := func(context.Context, ComponentPurgePlan) error { return nil }
	deny := func(context.Context, ComponentPurgePlan) error {
		return errors.New("policy v4 no longer schedules a purge")
	}

	// Inside the grace period: refused.
	if _, err := s.ExecuteComponentPurgePlan(ctx, plan.ID, allow, t0.Add(30*time.Minute)); !errors.Is(err, ErrPurgePlanNotExecutable) {
		t.Fatalf("in grace: %v", err)
	}
	// After grace, the current policy no longer authorises it: refused.
	if _, err := s.ExecuteComponentPurgePlan(ctx, plan.ID, deny, t0.Add(2*time.Hour)); !errors.Is(err, ErrPurgePlanNotExecutable) {
		t.Fatalf("recheck denied: %v", err)
	}
	// Without a recheck at all: refused.
	if _, err := s.ExecuteComponentPurgePlan(ctx, plan.ID, nil, t0.Add(2*time.Hour)); !errors.Is(err, ErrPurgePlanNotExecutable) {
		t.Fatalf("no recheck: %v", err)
	}
	if got := purgeCount(t, database, `SELECT COUNT(*) FROM actions WHERE tool = 'zed'`); got != 6 {
		t.Fatal("a refused scheduled plan deleted rows")
	}
	// Advance: grace elapsed -> eligible.
	if n, err := s.AdvanceComponentPurgePlans(ctx, t0.Add(2*time.Hour)); err != nil || n != 1 {
		t.Fatalf("advance: %d %v", n, err)
	}
	p, _ := s.ComponentPurgePlanByID(ctx, plan.ID)
	if p.State != PurgeEligible {
		t.Fatalf("state %s", p.State)
	}
	// Executes once authorised.
	if _, err := s.ExecuteComponentPurgePlan(ctx, plan.ID, allow, t0.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}

	// A second scheduled plan is cancelled before it runs.
	plan2, err := s.CreateComponentPurgePlan(ctx, ComponentPurgeSpec{Kind: PurgeScheduled, Component: "adapter.claude-code", Grace: time.Hour, Now: t0})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CancelComponentPurgePlan(ctx, plan2.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ExecuteComponentPurgePlan(ctx, plan2.ID, allow, t0.Add(2*time.Hour)); !errors.Is(err, ErrPurgePlanNotExecutable) {
		t.Fatalf("cancelled execute: %v", err)
	}
	if got := purgeCount(t, database, `SELECT COUNT(*) FROM actions WHERE tool = 'claude-code'`); got == 0 {
		t.Fatal("a cancelled plan deleted rows")
	}
}

// TestAdapterPurgeClampsSessionPushCursor pins ledger MODPKG-8: a component
// purge that deletes the newest sessions must bring the org push cursor
// down in its own transaction (the T-373 rule every session deleter
// follows), or the next session SQLite hands the freed rowid never ships.
func TestAdapterPurgeClampsSessionPushCursor(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	ingest := func(id, tool string) {
		t.Helper()
		if _, err := s.Ingest(ctx, []models.ToolEvent{{
			Tool: tool, SourceFile: "/t/" + id + ".jsonl", SourceEventID: id + ":1",
			SessionID: id, ProjectRoot: "/tmp/p_modpkg8", Timestamp: time.Now().UTC(),
			ActionType: models.ActionRunCommand, Target: "ls", RawToolName: "Bash", Success: true,
		}}, nil, IngestOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	ingest("c1", models.ToolClaudeCode)
	ingest("c2", models.ToolClaudeCode)
	ingest("z3", models.ToolZed) // the newest session belongs to the purged adapter
	maxIDs, err := s.CurrentMaxIDs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SavePushCursor(ctx, maxIDs); err != nil {
		t.Fatal(err)
	}
	plan, err := s.CreateComponentPurgePlan(ctx, ComponentPurgeSpec{Kind: PurgeInteractive, Component: "adapter.zed", CatalogVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.ExecuteComponentPurgePlan(ctx, plan.ID, nil, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Deleted["sessions"] != 1 {
		t.Fatalf("purge result %+v, want the zed session deleted", res)
	}
	ingest("c4", models.ToolClaudeCode) // SQLite hands it z3's rowid
	cur, err := s.LoadPushCursor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := s.SelectUnpushedSince(ctx, cur, 1<<20, "org-1", "dev@acme.example", ShareOptions{}, ScopeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var shipped []string
	for _, r := range batch.Sessions {
		shipped = append(shipped, r.ID)
	}
	if len(shipped) != 1 || shipped[0] != "c4" {
		t.Fatalf("sessions shipped after the purge = %v, want [c4]", shipped)
	}
}

func TestPurgeRefusesComponentsWithoutAReviewedPlan(t *testing.T) {
	s, _ := newTestStore(t)
	if _, err := s.CreateComponentPurgePlan(context.Background(), ComponentPurgeSpec{Kind: PurgeInteractive, Component: "codeintel"}); !errors.Is(err, ErrNoPurgePlan) {
		t.Fatalf("codeintel: %v", err)
	}
	if !HasPurgePlan("adapter.zed") || HasPurgePlan("terminals") {
		t.Fatal("HasPurgePlan table wrong")
	}
	if _, err := s.ComponentPurgePlanByID(context.Background(), "cpp_missing"); !errors.Is(err, ErrPurgePlanNotFound) {
		t.Fatalf("missing: %v", err)
	}
}

// purgeSessionListColumns are the node schema's JSON lists of session ids
// whose column name does not say session_id, so the schema scan cannot find
// them: each needs its remove_from_list decision.
var purgeSessionListColumns = map[string]bool{
	"commit_landings.contributors_json": true,
}

// purgeSchemaSessionColumns lists every (table, column) of the migrated
// node schema whose column name contains session_id or thread_id.
func purgeSchemaSessionColumns(t *testing.T, database *sql.DB) map[string]bool {
	t.Helper()
	rows, err := database.Query(`SELECT m.name, p.name FROM sqlite_master m, pragma_table_info(m.name) p
		WHERE m.type = 'table' AND m.name NOT LIKE 'sqlite_%'
		  AND (p.name LIKE '%session_id%' OR p.name LIKE '%thread_id%')`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var tbl, col string
		if err := rows.Scan(&tbl, &col); err != nil {
			t.Fatal(err)
		}
		out[tbl+"."+col] = true
	}
	return out
}

// TestPurgeSessionDecisionsCoverTheSchema pins ledger MODPKG-10: every
// session-keyed column of the node schema has exactly one reviewed adapter
// purge decision, and every decision names a real column. A new
// session-keyed table fails here until its purge decision is recorded in
// purgeSessionDecisions.
func TestPurgeSessionDecisionsCoverTheSchema(t *testing.T) {
	t.Parallel()
	_, database := newTestStore(t)
	schema := purgeSchemaSessionColumns(t, database)
	seen := map[string]int{}
	valid := map[purgeDecisionKind]bool{
		purgeKeepSession: true, purgeDeleteWithSession: true, purgeNullLink: true,
		purgeKeepDangling: true, purgeOwnerReconciles: true, purgeRemoveFromList: true,
	}
	hasColumn := func(tbl, col string) bool {
		var n int
		if err := database.QueryRow(`SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?`, tbl, col).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n == 1
	}
	for _, d := range purgeSessionDecisions {
		key := d.table + "." + d.column
		seen[key]++
		switch {
		case d.kind == purgeRemoveFromList:
			if !hasColumn(d.table, d.column) || !purgeSessionListColumns[key] {
				t.Errorf("remove_from_list %s: no such column, or not in purgeSessionListColumns", key)
			}
		case !schema[key]:
			t.Errorf("decision for %s names no session-keyed column of the schema", key)
		}
		if !valid[d.kind] {
			t.Errorf("%s: unknown decision kind %q", key, d.kind)
		}
		if strings.TrimSpace(d.reason) == "" {
			t.Errorf("%s: a decision needs its reviewed reason", key)
		}
		if d.otherSource != "" && d.kind != purgeKeepSession {
			t.Errorf("%s: otherSource only applies to keep_session", key)
		}
		if d.toolColumn != "" && (d.kind != purgeDeleteWithSession || !hasColumn(d.table, d.toolColumn)) {
			t.Errorf("%s: toolColumn %q needs delete_with_session and a real column", key, d.toolColumn)
		}
		if (d.keptCascade == "") != (d.keptCascadeTable == "") || (d.keptCascade == "") != (d.keptCascadeCount == "") || (d.keptCascade != "" && d.toolColumn == "") {
			t.Errorf("%s: keptCascade needs its table and a toolColumn", key)
		}
	}
	for key, n := range seen {
		if n > 1 {
			t.Errorf("%s has %d purge decisions, want exactly one", key, n)
		}
	}
	var missing []string
	for key := range purgeSessionListColumns {
		if seen[key] == 0 {
			missing = append(missing, key)
		}
	}
	for key := range schema {
		if seen[key] == 0 {
			missing = append(missing, key)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("session-keyed columns without a reviewed adapter purge decision (add a purgeSessionDecisions row, ledger MODPKG-10): %v", missing)
	}
	for _, deps := range [][]purgeDependent{purgeActionDependents, purgeTokenDependents} {
		for _, d := range deps {
			if !hasColumn(d.table, d.column) || !hasColumn(d.table, "session_id") {
				t.Errorf("dependent %s.%s: no such column (or no session_id)", d.table, d.column)
			}
		}
	}
}

// purgeSeedRow inserts one row into tbl with the given values and a
// placeholder for every other NOT NULL column without a default. It
// returns the rowid (0 for a WITHOUT ROWID table).
func purgeSeedRow(t *testing.T, database *sql.DB, seq *int, tbl string, set map[string]any) int64 {
	t.Helper()
	rows, err := database.Query(`SELECT name, type, "notnull", dflt_value IS NOT NULL, pk FROM pragma_table_info(?)`, tbl)
	if err != nil {
		t.Fatal(err)
	}
	var cols []string
	var args []any
	type colInfo struct {
		name, typ   string
		notnull, df bool
		pk          int
	}
	var infos []colInfo
	for rows.Next() {
		var c colInfo
		if err := rows.Scan(&c.name, &c.typ, &c.notnull, &c.df, &c.pk); err != nil {
			t.Fatal(err)
		}
		infos = append(infos, c)
	}
	rows.Close()
	for _, c := range infos {
		if v, ok := set[c.name]; ok {
			cols, args = append(cols, c.name), append(args, v)
			continue
		}
		if !c.notnull || c.df || (c.pk == 1 && strings.EqualFold(c.typ, "INTEGER")) {
			continue
		}
		*seq++
		var v any = fmt.Sprintf("seed-%d", *seq)
		switch {
		case strings.Contains(strings.ToUpper(c.typ), "INT"):
			v = int64(*seq)
		case strings.Contains(strings.ToUpper(c.typ), "REAL"):
			v = 0.5
		}
		cols, args = append(cols, c.name), append(args, v)
	}
	//nolint:gosec // test-only: table and columns come from the schema.
	q := `INSERT INTO ` + tbl + ` (` + strings.Join(cols, ", ") + `) VALUES (` + strings.TrimSuffix(strings.Repeat("?,", len(cols)), ",") + `)`
	r, err := database.Exec(q, args...)
	if err != nil {
		t.Fatalf("seed %s: %v", tbl, err)
	}
	id, _ := r.LastInsertId()
	return id
}

// TestAdapterPurgeAppliesSessionDecisions pins ledger MODPKG-10 end to
// end: one row per decision table hangs off a session the purge deletes,
// and each lands as its decision says (deleted, unlinked or untouched);
// tool-tagged rows of a kept session and the dependents of a purged action
// or token row go too, while another tool's rows stay; api_turns and
// otel_content keep the session they point at; the preview's estimate
// matches what the execute deletes.
func TestAdapterPurgeAppliesSessionDecisions(t *testing.T) {
	t.Parallel()
	s, database := newTestStore(t)
	ctx := context.Background()
	seedMixedAdapters(t, s)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := database.Exec(q, args...); err != nil {
			t.Fatalf("%q: %v", q, err)
		}
	}
	for _, id := range []string{"p1", "o1"} {
		exec(`INSERT INTO sessions (id, project_id, tool, started_at) VALUES (?, 1, 'zed', '2026-10-07T00:00:00Z')`, id)
	}
	seq := 0
	// Parents a foreign key needs, then the values a generic placeholder
	// would violate (CHECK constraints), per table.
	purgeSeedRow(t, database, &seq, "arena_runs", map[string]any{"id": "ar1"})
	purgeSeedRow(t, database, &seq, "benchmark_runs", map[string]any{"run_id": "br1"})
	attempt := purgeSeedRow(t, database, &seq, "benchmark_attempts", map[string]any{"run_id": "br1"})
	overrides := map[string]map[string]any{
		"arena_candidates":          {"run_id": "ar1"},
		"benchmark_session_members": {"run_id": "br1", "attempt_id": attempt},
		"org_intel_outbox":          {"trigger_kind": "background", "state": "pending"},
		"org_message_outbox":        {"kind": "post"},
		"mcp_relay_record": {
			"record_kind": "decision", "capture_level": "L1", "corr_confidence": "exact",
			"call_id": "call-1", "event_kind": "mcp_call", "decision": "allow",
		},
	}
	purgeSeedWith := func(tbl string, set map[string]any) map[string]any {
		out := map[string]any{}
		for k, v := range overrides[tbl] {
			out[k] = v
		}
		for k, v := range set {
			out[k] = v
		}
		return out
	}
	rowids := map[string]int64{}
	for _, d := range purgeSessionDecisions {
		switch d.kind {
		case purgeDeleteWithSession, purgeNullLink, purgeKeepDangling, purgeOwnerReconciles:
		default:
			continue
		}
		key := d.table + "." + d.column
		if d.table == "sessions" {
			exec(`UPDATE sessions SET parent_thread_id = 'z1' WHERE id = 'c1'`)
			continue
		}
		if d.kind == purgeOwnerReconciles && purgeCount(t, database, `SELECT COUNT(*) FROM `+d.table+` WHERE `+d.column+` = 'z1'`) > 0 {
			continue // the owner's trigger already queued it
		}
		set := map[string]any{d.column: "z1"}
		if d.toolColumn != "" {
			set[d.toolColumn] = "zed"
		}
		if d.column == "session_ids" {
			set[d.column] = `["z1"]`
		}
		rowids[key] = purgeSeedRow(t, database, &seq, d.table, purgeSeedWith(d.table, set))
	}
	// api_turns and otel_content keep their (zed) sessions.
	purgeSeedRow(t, database, &seq, "api_turns", purgeSeedWith("api_turns", map[string]any{"session_id": "p1"}))
	purgeSeedRow(t, database, &seq, "otel_content", purgeSeedWith("otel_content", map[string]any{"session_id": "o1"}))
	// The kept mixed session: a zed task item with a transition, a
	// claude-code task item; zed and claude-code account observations.
	purgeSeedRow(t, database, &seq, "task_items", purgeSeedWith("task_items", map[string]any{"session_id": "mixed", "tool": "zed", "key": "kz"}))
	purgeSeedRow(t, database, &seq, "task_transitions", purgeSeedWith("task_transitions", map[string]any{"session_id": "mixed", "key": "kz"}))
	purgeSeedRow(t, database, &seq, "task_items", purgeSeedWith("task_items", map[string]any{"session_id": "mixed", "tool": "claude-code", "key": "kc"}))
	purgeSeedRow(t, database, &seq, "tool_account_observations", purgeSeedWith("tool_account_observations", map[string]any{"session_id": "mixed", "tool": "zed"}))
	purgeSeedRow(t, database, &seq, "tool_account_observations", purgeSeedWith("tool_account_observations", map[string]any{"session_id": "mixed", "tool": "claude-code"}))
	// Dependents in the kept session: a file change of the zed action, a
	// cache event of a zed token row; and one of a claude-code action.
	var zedMixedAction, ccMixedAction int64
	if err := database.QueryRow(`SELECT id FROM actions WHERE session_id = 'mixed' AND tool = 'zed'`).Scan(&zedMixedAction); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT id FROM actions WHERE session_id = 'mixed' AND tool = 'claude-code'`).Scan(&ccMixedAction); err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO token_usage (session_id, timestamp, tool, model, input_tokens, output_tokens, source, reliability, source_file, source_event_id)
		VALUES ('mixed', '2026-10-07T00:00:02Z', 'zed', 'm', 1, 1, 'jsonl', 'estimated', 'f', 'mixed-zed-tok')`)
	var zedMixedToken int64
	if err := database.QueryRow(`SELECT id FROM token_usage WHERE source_event_id = 'mixed-zed-tok'`).Scan(&zedMixedToken); err != nil {
		t.Fatal(err)
	}
	purgeSeedRow(t, database, &seq, "file_changes", purgeSeedWith("file_changes", map[string]any{"session_id": "mixed", "action_id": zedMixedAction}))
	purgeSeedRow(t, database, &seq, "file_changes", purgeSeedWith("file_changes", map[string]any{"session_id": "mixed", "action_id": ccMixedAction}))
	purgeSeedRow(t, database, &seq, "cache_events", purgeSeedWith("cache_events", map[string]any{"session_id": "mixed", "token_usage_id": zedMixedToken}))

	plan, err := s.CreateComponentPurgePlan(ctx, ComponentPurgeSpec{Kind: PurgeInteractive, Component: "adapter.zed", CatalogVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.ExecuteComponentPurgePlan(ctx, plan.ID, nil, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	count := func(q string, args ...any) int { return purgeCount(t, database, q, args...) }
	if count(`SELECT COUNT(*) FROM sessions WHERE id = 'z1'`) != 0 {
		t.Fatalf("z1 was kept: %+v", res)
	}
	for _, id := range []string{"p1", "o1", "mixed"} {
		if count(`SELECT COUNT(*) FROM sessions WHERE id = ?`, id) != 1 {
			t.Errorf("session %s lost although another source references it", id)
		}
	}
	if count(`SELECT COUNT(*) FROM api_turns WHERE session_id = 'p1'`) != 1 || count(`SELECT COUNT(*) FROM otel_content WHERE session_id = 'o1'`) != 1 {
		t.Error("another source's api_turns / otel_content lost its session")
	}
	for _, d := range purgeSessionDecisions {
		key := d.table + "." + d.column
		switch d.kind {
		case purgeDeleteWithSession:
			//nolint:gosec // test-only literals from the decision table.
			if n := count(`SELECT COUNT(*) FROM ` + d.table + ` WHERE ` + d.column + ` = 'z1'`); n != 0 {
				t.Errorf("%s: %d rows of the purged session left (delete_with_session)", key, n)
			}
		case purgeNullLink:
			//nolint:gosec // as above.
			if n := count(`SELECT COUNT(*) FROM `+d.table+` WHERE rowid = ? AND `+d.column+` IS NULL`, rowids[key]); n != 1 {
				t.Errorf("%s: row not kept with a NULL link", key)
			}
		case purgeKeepDangling, purgeOwnerReconciles:
			if d.table == "sessions" {
				if count(`SELECT COUNT(*) FROM sessions WHERE id = 'c1' AND parent_thread_id = 'z1'`) != 1 {
					t.Errorf("%s rewritten", key)
				}
				continue
			}
			want := "z1"
			if d.column == "session_ids" {
				want = `["z1"]`
			}
			//nolint:gosec // as above.
			if n := count(`SELECT COUNT(*) FROM `+d.table+` WHERE `+d.column+` = ?`, want); n < 1 {
				t.Errorf("%s: row rewritten or deleted (%s)", key, d.kind)
			}
		}
	}
	if count(`SELECT COUNT(*) FROM spend_verdict_dirty WHERE session_id = 'z1'`) != 1 {
		t.Error("the spend verdict owner was not left a queued session")
	}
	// Kept session: tool-tagged rows of zed go (with the transition hung
	// off the zed item's key), claude-code rows stay.
	if count(`SELECT COUNT(*) FROM task_items WHERE session_id = 'mixed' AND tool = 'zed'`) != 0 ||
		count(`SELECT COUNT(*) FROM task_transitions WHERE session_id = 'mixed' AND key = 'kz'`) != 0 {
		t.Error("zed task rows of the kept session survived")
	}
	if count(`SELECT COUNT(*) FROM task_items WHERE session_id = 'mixed' AND tool = 'claude-code'`) != 1 {
		t.Error("another tool's task item in the kept session was deleted")
	}
	if count(`SELECT COUNT(*) FROM tool_account_observations WHERE session_id = 'mixed' AND tool = 'zed'`) != 0 ||
		count(`SELECT COUNT(*) FROM tool_account_observations WHERE session_id = 'mixed' AND tool = 'claude-code'`) != 1 {
		t.Error("kept-session account observations: zed must go, claude-code must stay")
	}
	if count(`SELECT COUNT(*) FROM file_changes WHERE action_id = ?`, zedMixedAction) != 0 ||
		count(`SELECT COUNT(*) FROM file_changes WHERE action_id = ?`, ccMixedAction) != 1 {
		t.Error("file_changes dependents: the purged action's must go, another tool's must stay")
	}
	if count(`SELECT COUNT(*) FROM cache_events WHERE token_usage_id = ?`, zedMixedToken) != 0 {
		t.Error("a cache event of a purged token row survived")
	}
	// The preview's estimate equals what the execute deleted, per derived
	// table.
	for tbl, n := range res.Deleted {
		switch tbl {
		case "actions", "token_usage", "compaction_events", "sessions":
			continue
		}
		if plan.Counts[tbl] != n {
			t.Errorf("preview estimate %s = %d, executed %d", tbl, plan.Counts[tbl], n)
		}
	}
	if res.Nulled["process_runs"] != 1 || res.Nulled["summary_calls"] != 1 {
		t.Errorf("nulled: %v", res.Nulled)
	}
}

// TestListScheduledComponentPurgePlans pins the runner seam (T-682): only
// scheduled plans are listed, oldest first, with their state and version.
func TestListScheduledComponentPurgePlans(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 8, 10, 0, 0, 0, time.UTC)
	if _, err := s.CreateComponentPurgePlan(ctx, ComponentPurgeSpec{Kind: PurgeInteractive, Component: "adapter.codex", Now: t0}); err != nil {
		t.Fatal(err)
	}
	a, err := s.CreateComponentPurgePlan(ctx, ComponentPurgeSpec{Kind: PurgeScheduled, Component: "adapter.codex", PolicyVersion: "v1", Now: t0})
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.CreateComponentPurgePlan(ctx, ComponentPurgeSpec{Kind: PurgeScheduled, Component: "adapter.cline", PolicyVersion: "v1", Now: t0.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CancelComponentPurgePlan(ctx, b.ID); err != nil {
		t.Fatal(err)
	}
	got, err := s.ListScheduledComponentPurgePlans(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ID != a.ID || got[1].ID != b.ID || got[0].State != PurgeGracePending || got[1].State != PurgeCancelled || got[0].PolicyVersion != "v1" {
		t.Fatalf("listed = %+v", got)
	}
}

// TestAdapterPurgeRemovesSessionFromCommitContributors pins the
// remove_from_list decision for commit_landings.contributors_json: a purged
// session's opaque id leaves every contributor list that holds it, the
// landing row itself stays, and the ids of sessions the purge keeps (another
// tool's, or one another source references) stay in the list in order.
func TestAdapterPurgeRemovesSessionFromCommitContributors(t *testing.T) {
	t.Parallel()
	s, database := newTestStore(t)
	ctx := context.Background()
	seedMixedAdapters(t, s)
	seq := 0
	lists := []struct{ before, after string }{
		{`["z1","c1"]`, `["c1"]`},
		{`["mixed","z1","z2"]`, `["mixed"]`},
		{`["z2"]`, `[]`},
		{`["c1"]`, `["c1"]`},
		{`[]`, `[]`},
	}
	ids := make([]int64, len(lists))
	for i, l := range lists {
		cid := purgeSeedRow(t, database, &seq, "project_commits", map[string]any{"project_id": 1, "sha": fmt.Sprintf("%040d", i)})
		purgeSeedRow(t, database, &seq, "commit_landings", map[string]any{
			"commit_id": cid, "project_id": 1, "status": "landed", "evaluated_at": "2026-10-07T00:00:00Z", "contributors_json": l.before,
		})
		ids[i] = cid
	}
	plan, err := s.CreateComponentPurgePlan(ctx, ComponentPurgeSpec{Kind: PurgeInteractive, Component: "adapter.zed", CatalogVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.ExecuteComponentPurgePlan(ctx, plan.ID, nil, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	for i, l := range lists {
		var got string
		if err := database.QueryRow(`SELECT contributors_json FROM commit_landings WHERE commit_id = ?`, ids[i]).Scan(&got); err != nil {
			t.Fatalf("landing %d: %v", i, err)
		}
		if got != l.after {
			t.Errorf("contributors %s after the zed purge = %s, want %s", l.before, got, l.after)
		}
	}
	// z1 rewrites lists 0 and 1, z2 rewrites lists 1 and 2: one count per
	// list per purged session.
	if res.Nulled["commit_landings"] != 4 {
		t.Errorf("rewritten contributor lists = %d, want 4", res.Nulled["commit_landings"])
	}
}
