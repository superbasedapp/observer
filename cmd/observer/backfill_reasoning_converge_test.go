package main

// Tests for --reasoning-converge. Two layers, deliberately:
//
//   - planReasoningSession is PURE, so B3's four threading semantics are
//     table-tested directly at the layer that owns them. Each mutation
//     proof names the exact line that must break for its row to fail.
//   - the DB layer is exercised end-to-end over a TEMP fixture DB built
//     from the real migrations, covering the dependency protocol, the
//     transaction, and idempotency on re-run.

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
)

// res builds a residue row in the planner's shape.
func res(id int64, tool, target, body string) reasoningAction {
	return reasoningAction{
		ID:      id,
		Residue: &reasoningResidue{Tool: tool, RawToolName: tool + ".reasoning", Target: target, RawToolOutput: body},
	}
}

// act builds an ordinary (non-residue) action row.
func act(id int64, actionType, preceding string) reasoningAction {
	return reasoningAction{ID: id, ActionType: actionType, PrecedingReasoning: preceding}
}

// outcomeOf returns the disposition recorded for a residue id.
func outcomeOf(p reasoningPlan, id int64) reasoningResidueOutcome {
	for _, d := range p.Dispositions {
		if d.ResidueID == id {
			return d.Outcome
		}
	}
	return "<none>"
}

// carryOnto returns the text planned for an action id, or "" if none.
func carryOnto(p reasoningPlan, actionID int64) string {
	for _, c := range p.Carries {
		if c.ActionID == actionID {
			return c.Text
		}
	}
	return ""
}

// TestPlanReasoningSession covers the happy path plus every B3 semantic.
//
// MUTATION PROOF MAP — the implementation line each row kills, and the
// mutant that was run against it (results in the session report):
//
//	happy path              → the carry append in planReasoningSession
//	consumed-once           → `hasPending = false` after the successor
//	last-wins               → discard(outcomeSuperseded) before re-arming
//	turn-boundary-discarded → the `a.ActionType == "user_prompt"` branch
//	never-overwrite         → the `a.PrecedingReasoning == ""` case
//	already-preserved       → the strings.Contains case
//
// DECOY CASES are placed AFTER the real bindings on purpose: a mutant
// that satisfies a decoy by accident still has to fail its own row.
func TestPlanReasoningSession(t *testing.T) {
	tests := []struct {
		name string
		// in is one session's timeline in (timestamp, id) order.
		in []reasoningAction
		// wantOutcome maps residue id → expected outcome.
		wantOutcome map[int64]reasoningResidueOutcome
		// wantCarry maps successor action id → expected carried text.
		wantCarry map[int64]string
		// wantCarryCount pins the TOTAL number of writes, so a mutant
		// that carries onto extra rows cannot pass by matching the map.
		wantCarryCount int
	}{
		{
			name: "happy path — reasoning carries onto the next action",
			in: []reasoningAction{
				res(1, "crush", "thought preview", "thought preview and then some more"),
				act(2, "file_read", ""),
			},
			wantOutcome:    map[int64]reasoningResidueOutcome{1: outcomeCarried},
			wantCarry:      map[int64]string{2: "thought preview and then some more"},
			wantCarryCount: 1,
		},
		{
			name: "consumed-once — the second successor gets nothing",
			in: []reasoningAction{
				res(1, "crush", "only once", ""),
				act(2, "file_read", ""),
				act(3, "file_write", ""),
			},
			wantOutcome:    map[int64]reasoningResidueOutcome{1: outcomeCarried},
			wantCarry:      map[int64]string{2: "only once", 3: ""},
			wantCarryCount: 1,
		},
		{
			name: "last-wins — the later reasoning reaches the successor",
			in: []reasoningAction{
				res(1, "codex", "first thought", ""),
				res(2, "codex", "second thought", ""),
				act(3, "run_command", ""),
			},
			wantOutcome: map[int64]reasoningResidueOutcome{
				1: outcomeSuperseded,
				2: outcomeCarried,
			},
			wantCarry:      map[int64]string{3: "second thought"},
			wantCarryCount: 1,
		},
		{
			name: "turn-boundary-discarded — a user_prompt drops it",
			in: []reasoningAction{
				res(1, "pi", "pre-boundary thought", ""),
				act(2, "user_prompt", ""),
				act(3, "file_read", ""),
			},
			wantOutcome:    map[int64]reasoningResidueOutcome{1: outcomeTurnBoundary},
			wantCarry:      map[int64]string{3: ""},
			wantCarryCount: 0,
		},
		{
			name: "never-overwrite — a populated successor keeps its text",
			in: []reasoningAction{
				res(1, "opencode", "the residue thought", ""),
				act(2, "file_read", "a completely different preamble"),
			},
			wantOutcome:    map[int64]reasoningResidueOutcome{1: outcomeOccupied},
			wantCarry:      map[int64]string{2: ""},
			wantCarryCount: 0,
		},
		{
			name: "already-preserved — the successor already contains the text",
			in: []reasoningAction{
				res(1, "cowork", "shared thought", ""),
				act(2, "file_read", "shared thought"),
			},
			wantOutcome:    map[int64]reasoningResidueOutcome{1: outcomePreserved},
			wantCarry:      map[int64]string{2: ""},
			wantCarryCount: 0,
		},
		{
			name: "no successor — the session ends on the reasoning row",
			in: []reasoningAction{
				act(1, "file_read", ""),
				res(2, "hermes", "trailing thought", ""),
			},
			wantOutcome:    map[int64]reasoningResidueOutcome{2: outcomeNoSuccessor},
			wantCarryCount: 0,
		},
		{
			name: "divergent body — never converged, never deleted",
			in: []reasoningAction{
				res(1, "cursor", "the user wants a summary", "I have reviewed the project"),
				act(2, "file_read", ""),
			},
			wantOutcome:    map[int64]reasoningResidueOutcome{1: outcomeDivergent},
			wantCarry:      map[int64]string{2: ""},
			wantCarryCount: 0,
		},

		// ---- DECOYS (after the real bindings, on purpose) ----------
		{
			name: "decoy — a lone ordinary action plans nothing",
			in: []reasoningAction{
				act(1, "file_read", ""),
				act(2, "file_write", ""),
			},
			wantOutcome:    map[int64]reasoningResidueOutcome{},
			wantCarryCount: 0,
		},
		{
			name: "decoy — user_prompt AFTER the carry does not undo it",
			in: []reasoningAction{
				res(1, "crush", "carried before the boundary", ""),
				act(2, "file_read", ""),
				act(3, "user_prompt", ""),
			},
			wantOutcome:    map[int64]reasoningResidueOutcome{1: outcomeCarried},
			wantCarry:      map[int64]string{2: "carried before the boundary"},
			wantCarryCount: 1,
		},
		{
			name: "decoy — last-wins across a boundary still discards the first",
			in: []reasoningAction{
				res(1, "codex", "before boundary", ""),
				act(2, "user_prompt", ""),
				res(3, "codex", "after boundary", ""),
				act(4, "run_command", ""),
			},
			wantOutcome: map[int64]reasoningResidueOutcome{
				1: outcomeTurnBoundary,
				3: outcomeCarried,
			},
			wantCarry:      map[int64]string{4: "after boundary"},
			wantCarryCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan := planReasoningSession(tt.in)
			if len(plan.Carries) != tt.wantCarryCount {
				t.Errorf("carry count = %d, want %d (carries: %+v)", len(plan.Carries), tt.wantCarryCount, plan.Carries)
			}
			for id, want := range tt.wantOutcome {
				if got := outcomeOf(plan, id); got != want {
					t.Errorf("outcome of residue %d = %q, want %q", id, got, want)
				}
			}
			if len(plan.Dispositions) != len(tt.wantOutcome) {
				t.Errorf("disposition count = %d, want %d (%+v)", len(plan.Dispositions), len(tt.wantOutcome), plan.Dispositions)
			}
			for id, want := range tt.wantCarry {
				if got := carryOnto(plan, id); got != want {
					t.Errorf("carry onto %d = %q, want %q", id, got, want)
				}
			}
		})
	}
}

// TestPlanReasoningSessionNeverCrossesSessions pins the SESSION-SCOPED
// semantic at the layer that owns it: the planner is handed exactly one
// session's rows, so the DB layer's per-session loop is the guard. Two
// sessions planned separately must never share a carry — proved by
// planning them and checking the union of carries against the per-session
// action ids.
func TestPlanReasoningSessionNeverCrossesSessions(t *testing.T) {
	sessionA := []reasoningAction{res(1, "crush", "thought A", "")}
	sessionB := []reasoningAction{act(2, "file_read", "")}

	planA := planReasoningSession(sessionA)
	planB := planReasoningSession(sessionB)

	if len(planA.Carries) != 0 {
		t.Errorf("session A carried %d time(s); its reasoning has no successor IN ITS OWN session", len(planA.Carries))
	}
	if outcomeOf(planA, 1) != outcomeNoSuccessor {
		t.Errorf("session A residue outcome = %q, want %q", outcomeOf(planA, 1), outcomeNoSuccessor)
	}
	if len(planB.Carries) != 0 {
		t.Errorf("session B carried %d time(s); it holds no reasoning row", len(planB.Carries))
	}
	// The concatenation is what a session-blind implementation would see.
	// It MUST NOT be what the pass plans.
	if blind := planReasoningSession(append(append([]reasoningAction{}, sessionA...), sessionB...)); len(blind.Carries) != 1 {
		t.Fatalf("control: a session-blind walk should carry once, got %d — the control itself is wrong", len(blind.Carries))
	}
}

// TestCarryText pins which of the two columns is carried, and which
// shapes refuse to converge at all.
func TestCarryText(t *testing.T) {
	tests := []struct {
		name           string
		target, body   string
		wantText       string
		wantConvergeOK bool
	}{
		{"body extends target — carry the full body", "abc", "abcdef", "abcdef", true},
		{"body equals target — carry either", "abc", "abc", "abc", true},
		{"no body — carry the preview", "abc", "", "abc", true},
		{"body diverges from target — refuse", "abc", "xyz", "", false},
		{"both empty — refuse", "", "", "", false},
		{"body without a target to prove it against — refuse", "", "xyz", "", false},
		// Decoy: a body that CONTAINS target but does not start with it
		// is not a prefix-extension and must still be refused.
		{"decoy — body contains target mid-string — refuse", "abc", "zzabcdef", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := reasoningResidue{Target: tt.target, RawToolOutput: tt.body}.carryText()
			if ok != tt.wantConvergeOK {
				t.Fatalf("convergeable = %v, want %v", ok, tt.wantConvergeOK)
			}
			if got != tt.wantText {
				t.Errorf("text = %q, want %q", got, tt.wantText)
			}
		})
	}
}

// --- DB layer -------------------------------------------------------

// seedReasoningFixture builds a temp DB on the real migrations and seeds
// one project, one session, and the rows the caller describes.
func seedReasoningFixture(t *testing.T, ctx context.Context, rows []fixtureRow) *sql.DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "obs.db")
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })

	if _, err := database.ExecContext(ctx,
		`INSERT INTO projects (id, root_path, created_at) VALUES (1, '/tmp/rc', '2026-07-31T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, r := range rows {
		if !seen[r.session] {
			seen[r.session] = true
			if _, err := database.ExecContext(ctx,
				`INSERT INTO sessions (id, tool, started_at, project_id) VALUES (?, ?, '2026-07-31T00:00:00Z', 1)`,
				r.session, r.tool); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := database.ExecContext(ctx,
			`INSERT INTO actions (id, session_id, project_id, timestamp, action_type, tool,
			                      raw_tool_name, target, raw_tool_output, preceding_reasoning,
			                      source_file, source_event_id)
			 VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			r.id, r.session, r.ts, r.actionType, r.tool, nullIfEmpty(r.rawName),
			nullIfEmpty(r.target), nullIfEmpty(r.body), nullIfEmpty(r.preceding),
			fmt.Sprintf("/tmp/rc/%s.jsonl", r.session), fmt.Sprintf("e%d", r.id)); err != nil {
			t.Fatal(err)
		}
	}
	return database
}

type fixtureRow struct {
	id         int64
	session    string
	ts         string
	actionType string
	tool       string
	rawName    string
	target     string
	body       string
	preceding  string
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func rcScanInt(t *testing.T, ctx context.Context, database *sql.DB, q string, args ...any) int {
	t.Helper()
	var n int
	if err := database.QueryRowContext(ctx, q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func rcScanStr(t *testing.T, ctx context.Context, database *sql.DB, q string, args ...any) string {
	t.Helper()
	var s sql.NullString
	if err := database.QueryRowContext(ctx, q, args...).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s.String
}

// TestBackfillReasoningConverge_DryRunThenApply is the end-to-end case:
// dry run must write NOTHING, apply must carry + delete + clear the
// dependent rows, and a second apply must be a no-op.
func TestBackfillReasoningConverge_DryRunThenApply(t *testing.T) {
	ctx := context.Background()
	database := seedReasoningFixture(t, ctx, []fixtureRow{
		// s1: a plain carry, plus the excerpt that would become a
		// searchable ghost if the dependency protocol were skipped.
		{
			id: 1, session: "s1", ts: "2026-07-31T00:00:01Z", actionType: "task_complete", tool: "crush",
			rawName: "crush.reasoning", target: "the preview", body: "the preview plus the rest of the body",
		},
		{id: 2, session: "s1", ts: "2026-07-31T00:00:02Z", actionType: "file_read", tool: "crush"},
		// s2: never-overwrite — the row is retained by default.
		{
			id: 3, session: "s2", ts: "2026-07-31T00:00:01Z", actionType: "task_complete", tool: "opencode",
			rawName: "opencode.reasoning", target: "residue thought",
		},
		{
			id: 4, session: "s2", ts: "2026-07-31T00:00:02Z", actionType: "file_read", tool: "opencode",
			preceding: "a different preamble entirely",
		},
		// s3: a NON-candidate pair that must never be touched — devin's
		// deliberate task_complete branch (079 excludes it with evidence).
		{
			id: 5, session: "s3", ts: "2026-07-31T00:00:01Z", actionType: "task_complete", tool: "devin",
			rawName: "devin.assistant_message", target: "a real completion",
		},
		{id: 6, session: "s3", ts: "2026-07-31T00:00:02Z", actionType: "file_read", tool: "devin"},
	})
	if _, err := database.ExecContext(ctx,
		`INSERT INTO action_excerpts (action_id, excerpt) VALUES (1, 'ghost bait')`); err != nil {
		t.Fatal(err)
	}

	// --- dry run: reports, writes nothing -------------------------
	dry, err := backfillReasoningConverge(ctx, database, false, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if dry.RowsExamined != 2 {
		t.Errorf("dry RowsExamined = %d, want 2 (devin must not be a candidate)", dry.RowsExamined)
	}
	if dry.Carried != 1 || dry.RetainedOccupied != 1 || dry.RowsDeleted != 1 {
		t.Errorf("dry plan = carried %d / occupied %d / deleted %d, want 1 / 1 / 1",
			dry.Carried, dry.RetainedOccupied, dry.RowsDeleted)
	}
	if dry.ExcerptsDeleted != 1 {
		t.Errorf("dry ExcerptsDeleted = %d, want 1", dry.ExcerptsDeleted)
	}
	if n := rcScanInt(t, ctx, database, `SELECT COUNT(*) FROM actions WHERE id = 1`); n != 1 {
		t.Errorf("dry run deleted the residue row — it must write nothing")
	}
	if got := rcScanStr(t, ctx, database, `SELECT preceding_reasoning FROM actions WHERE id = 2`); got != "" {
		t.Errorf("dry run wrote preceding_reasoning = %q — it must write nothing", got)
	}

	// --- apply ----------------------------------------------------
	got, err := backfillReasoningConverge(ctx, database, true, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Carried != 1 || got.RowsDeleted != 1 {
		t.Errorf("apply = carried %d / deleted %d, want 1 / 1", got.Carried, got.RowsDeleted)
	}
	if want := "the preview plus the rest of the body"; rcScanStr(t, ctx, database,
		`SELECT preceding_reasoning FROM actions WHERE id = 2`) != want {
		t.Errorf("successor did not receive the FULL body")
	}
	if n := rcScanInt(t, ctx, database, `SELECT COUNT(*) FROM actions WHERE id = 1`); n != 0 {
		t.Errorf("carried residue row survived the apply")
	}
	if n := rcScanInt(t, ctx, database, `SELECT COUNT(*) FROM action_excerpts WHERE action_id = 1`); n != 0 {
		t.Errorf("action_excerpts row survived — FTS5 search never joins actions, so this is a searchable ghost")
	}
	if n := rcScanInt(t, ctx, database, `SELECT COUNT(*) FROM actions WHERE id = 3`); n != 1 {
		t.Errorf("never-overwrite row was deleted — its text exists nowhere else")
	}
	if n := rcScanInt(t, ctx, database, `SELECT COUNT(*) FROM actions WHERE id = 5`); n != 1 {
		t.Errorf("devin's deliberate task_complete row was deleted — it is not a B3 candidate")
	}

	// --- idempotency: a second apply changes nothing ---------------
	again, err := backfillReasoningConverge(ctx, database, true, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if again.Carried != 0 || again.RowsDeleted != 0 {
		t.Errorf("re-run = carried %d / deleted %d, want 0 / 0 (must be a no-op)", again.Carried, again.RowsDeleted)
	}
	if again.RowsExamined != 1 || again.RetainedOccupied != 1 {
		t.Errorf("re-run = examined %d / occupied %d, want 1 / 1 (the retained row stays retained)",
			again.RowsExamined, again.RetainedOccupied)
	}
	if n := rcScanInt(t, ctx, database, `SELECT COUNT(*) FROM actions WHERE id = 2 AND preceding_reasoning = 'the preview plus the rest of the body'`); n != 1 {
		t.Errorf("re-run disturbed the carried text")
	}
}

// TestBackfillReasoningConverge_NeverCrossesSessionID pins the
// session-scoping at the DB layer: a reasoning row in s1 and an
// unrelated action in s2 that is LATER in wall-clock order must not be
// paired, even though a session-blind ORDER BY timestamp would pair them.
func TestBackfillReasoningConverge_NeverCrossesSessionID(t *testing.T) {
	ctx := context.Background()
	database := seedReasoningFixture(t, ctx, []fixtureRow{
		{
			id: 1, session: "s1", ts: "2026-07-31T00:00:01Z", actionType: "task_complete", tool: "crush",
			rawName: "crush.reasoning", target: "s1 thought",
		},
		{id: 2, session: "s2", ts: "2026-07-31T00:00:02Z", actionType: "file_read", tool: "crush"},
	})
	got, err := backfillReasoningConverge(ctx, database, true, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Carried != 0 || got.RetainedNoSuccessor != 1 {
		t.Errorf("carried %d / no-successor %d, want 0 / 1 — reasoning crossed a session id",
			got.Carried, got.RetainedNoSuccessor)
	}
	if p := rcScanStr(t, ctx, database, `SELECT preceding_reasoning FROM actions WHERE id = 2`); p != "" {
		t.Errorf("s2's action received s1's reasoning (%q) — sessions must never mix", p)
	}
	if n := rcScanInt(t, ctx, database, `SELECT COUNT(*) FROM actions WHERE id = 1`); n != 1 {
		t.Errorf("the uncarried residue row was deleted — its text would be destroyed")
	}
}

// TestBackfillReasoningConverge_DiscardUnresolved proves the opt-in wider
// delete does what its help text says, and that divergent-body rows stay
// out of reach even then.
func TestBackfillReasoningConverge_DiscardUnresolved(t *testing.T) {
	ctx := context.Background()
	database := seedReasoningFixture(t, ctx, []fixtureRow{
		{
			id: 1, session: "s1", ts: "2026-07-31T00:00:01Z", actionType: "task_complete", tool: "opencode",
			rawName: "opencode.reasoning", target: "residue thought",
		},
		{
			id: 2, session: "s1", ts: "2026-07-31T00:00:02Z", actionType: "file_read", tool: "opencode",
			preceding: "a different preamble",
		},
		{
			id: 3, session: "s2", ts: "2026-07-31T00:00:01Z", actionType: "task_complete", tool: "cursor",
			rawName: "cursor.thinking", target: "the user wants a summary", body: "I have reviewed the project",
		},
		{id: 4, session: "s2", ts: "2026-07-31T00:00:02Z", actionType: "file_read", tool: "cursor"},
	})
	got, err := backfillReasoningConverge(ctx, database, true, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.RowsDeleted != 1 {
		t.Errorf("RowsDeleted = %d, want 1 (the occupied row only)", got.RowsDeleted)
	}
	if got.SkippedDivergent != 1 {
		t.Errorf("SkippedDivergent = %d, want 1", got.SkippedDivergent)
	}
	if got.UnresolvedBytes != int64(len("residue thought")) {
		t.Errorf("UnresolvedBytes = %d, want %d", got.UnresolvedBytes, len("residue thought"))
	}
	if n := rcScanInt(t, ctx, database, `SELECT COUNT(*) FROM actions WHERE id = 1`); n != 0 {
		t.Errorf("--discard-unresolved did not delete the occupied row")
	}
	if n := rcScanInt(t, ctx, database, `SELECT COUNT(*) FROM actions WHERE id = 3`); n != 1 {
		t.Errorf("a divergent-body row was deleted — it is out of reach under BOTH settings")
	}
}

// TestBackfillReasoningConverge_ReportNamesTheLoss pins the operator-
// facing honesty: the dry-run report must state how many rows are
// retained and how many bytes a wider delete would destroy.
func TestBackfillReasoningConverge_ReportNamesTheLoss(t *testing.T) {
	ctx := context.Background()
	database := seedReasoningFixture(t, ctx, []fixtureRow{
		{
			id: 1, session: "s1", ts: "2026-07-31T00:00:01Z", actionType: "task_complete", tool: "opencode",
			rawName: "opencode.reasoning", target: "residue thought",
		},
		{
			id: 2, session: "s1", ts: "2026-07-31T00:00:02Z", actionType: "file_read", tool: "opencode",
			preceding: "a different preamble",
		},
	})
	var out strings.Builder
	if _, err := backfillReasoningConverge(ctx, database, false, false, &out); err != nil {
		t.Fatal(err)
	}
	report := out.String()
	for _, want := range []string{
		"dry run",
		"nothing written (dry run)",
		"are RETAINED",
		fmt.Sprintf("destroy %d byte(s)", len("residue thought")),
		"--reasoning-converge-discard-unresolved",
		"NOT retracted",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("report is missing %q\n---\n%s", want, report)
		}
	}
}
