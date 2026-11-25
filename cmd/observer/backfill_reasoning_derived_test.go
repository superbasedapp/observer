package main

import (
	"context"
	"testing"
)

// TestBackfillReasoningConverge_DeletesDerivedRows pins MISC2-02 on the
// reasoning backfill: a file_changes or task_transitions row keyed to a
// residue row the pass deletes goes with it in the apply transaction (the
// dry run counts it and writes nothing), as the component purge and
// retention do. Neither table has a foreign key to actions, so before this a
// deleted row left them as orphans. The successor's own rows are kept.
func TestBackfillReasoningConverge_DeletesDerivedRows(t *testing.T) {
	ctx := context.Background()
	database := seedReasoningFixture(t, ctx, []fixtureRow{
		{
			id: 1, session: "s1", ts: "2026-07-31T00:00:01Z", actionType: "task_complete", tool: "crush",
			rawName: "crush.reasoning", target: "the preview", body: "the preview plus the rest",
		},
		{id: 2, session: "s1", ts: "2026-07-31T00:00:02Z", actionType: "edit_file", tool: "crush"},
	})
	for _, q := range []string{
		`INSERT INTO file_changes (session_id, project_id, action_id, file_path_hash, actor, source)
		 VALUES ('s1', 1, 1, 'h-residue', 'ai', 'edit'), ('s1', 1, 2, 'h-successor', 'ai', 'edit')`,
		`INSERT INTO task_transitions (session_id, key, to_status, ts, action_id, source_event_id)
		 VALUES ('s1', 'k-residue', 'completed', '2026-07-31T00:00:01Z', 1, 'e1'),
		        ('s1', 'k-successor', 'completed', '2026-07-31T00:00:02Z', 2, 'e2')`,
	} {
		if _, err := database.ExecContext(ctx, q); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	derived := func(actionID int) int {
		return rcScanInt(t, ctx, database, `SELECT
			(SELECT COUNT(*) FROM file_changes WHERE action_id = ?) +
			(SELECT COUNT(*) FROM task_transitions WHERE action_id = ?)`, actionID, actionID)
	}

	dry, err := backfillReasoningConverge(ctx, database, false, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if dry.RowsDeleted != 1 || dry.DerivedRowsDeleted != 2 {
		t.Errorf("dry run = %d row(s), %d derived; want 1 and 2", dry.RowsDeleted, dry.DerivedRowsDeleted)
	}
	if n := derived(1); n != 2 {
		t.Errorf("dry run removed derived rows (%d left, want 2): it must write nothing", n)
	}

	got, err := backfillReasoningConverge(ctx, database, true, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.RowsDeleted != 1 || got.DerivedRowsDeleted != 2 {
		t.Errorf("apply = %d row(s), %d derived; want 1 and 2", got.RowsDeleted, got.DerivedRowsDeleted)
	}
	if n := derived(1); n != 0 {
		t.Errorf("%d file_changes/task_transitions row(s) of the deleted residue row survived as orphans", n)
	}
	if n := derived(2); n != 2 {
		t.Errorf("the successor's derived rows = %d, want 2 (only the deleted row's go)", n)
	}
}
