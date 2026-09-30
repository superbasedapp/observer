package store

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestIngest_SessionEndStampsEndedAt pins the lifecycle rule end to end:
// a session_end action closes the session (sessions.ended_at = its
// timestamp), rows a host writes after its end hook (a turn-evidence row)
// leave it closed, a later human turn reopens it (resume under the same
// id), and the next session_end closes it again. The shapes are Cursor's
// hook rows (sessionStart / beforeSubmitPrompt / sessionEnd) and its CLI
// debug-log turn row, but nothing here is Cursor-specific: the decision is
// by action type.
func TestIngest_SessionEndStampsEndedAt(t *testing.T) {
	st, db := newTestStore(t)
	ctx := context.Background()
	root := t.TempDir()
	const sid = "c0c0c001-0000-4000-8000-00000000e0d1"
	base := time.Date(2026, 9, 27, 11, 13, 13, 0, time.UTC)
	ev := func(id, action string, at time.Time) models.ToolEvent {
		return models.ToolEvent{
			SessionID: sid, ProjectRoot: root, Timestamp: at, Tool: models.ToolCursor,
			SourceFile: "cursor:hook", SourceEventID: id, ActionType: action, Success: true,
		}
	}
	endedAt := func() sql.NullString {
		t.Helper()
		var v sql.NullString
		if err := db.QueryRow(`SELECT ended_at FROM sessions WHERE id = ?`, sid).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	ingest := func(evs ...models.ToolEvent) {
		t.Helper()
		if _, err := st.Ingest(ctx, evs, nil, IngestOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	end1 := base.Add(31952 * time.Millisecond)
	ingest(ev(sid+":sessionStart", models.ActionSessionStart, base), ev("g1:beforeSubmitPrompt", models.ActionUserPrompt, base.Add(10*time.Second)))
	if v := endedAt(); v.Valid {
		t.Fatalf("open session ended_at = %q, want NULL", v.String)
	}
	// The end hook arrives in its own batch, as the live hook ingests it.
	ingest(ev(sid+":sessionEnd", models.ActionSessionEnd, end1))
	if v := endedAt(); !v.Valid || v.String != end1.Format(time.RFC3339Nano) {
		t.Fatalf("after sessionEnd ended_at = %+v, want %s", v, end1.Format(time.RFC3339Nano))
	}
	// A turn-evidence row timestamped after the end hook does not reopen.
	late := ev("cursor-cli-turn:t1:unfinished", models.ActionTurnAborted, end1.Add(time.Second))
	late.SourceFile, late.Success = "cli.log", false
	ingest(late)
	if v := endedAt(); !v.Valid || v.String != end1.Format(time.RFC3339Nano) {
		t.Fatalf("after late evidence row ended_at = %+v, want unchanged", v)
	}
	// A resumed conversation: a later prompt reopens, the next end closes.
	ingest(ev("g2:beforeSubmitPrompt", models.ActionUserPrompt, base.Add(5*time.Minute)))
	if v := endedAt(); v.Valid {
		t.Fatalf("after resume ended_at = %q, want NULL", v.String)
	}
	end2 := base.Add(6 * time.Minute)
	ingest(ev(sid+":sessionEnd:2", models.ActionSessionEnd, end2))
	if v := endedAt(); !v.Valid || v.String != end2.Format(time.RFC3339Nano) {
		t.Fatalf("after second end ended_at = %+v, want %s", v, end2.Format(time.RFC3339Nano))
	}
	// A transcript backfill that re-delivers an OLD prompt (before end2)
	// must not reopen.
	ingest(ev("g0:beforeSubmitPrompt", models.ActionUserPrompt, base.Add(time.Second)))
	if v := endedAt(); !v.Valid || v.String != end2.Format(time.RFC3339Nano) {
		t.Fatalf("after replayed old prompt ended_at = %+v, want unchanged", v)
	}
}

// A session with no session_end row keeps whatever ended_at it had: the
// refresh never clears a value it did not decide.
func TestIngest_NoSessionEndLeavesEndedAtAlone(t *testing.T) {
	st, db := newTestStore(t)
	ctx := context.Background()
	root := t.TempDir()
	pid, err := st.UpsertProject(ctx, root, "")
	if err != nil {
		t.Fatal(err)
	}
	ended := time.Date(2026, 9, 27, 10, 0, 0, 0, time.UTC)
	if err := st.UpsertSession(ctx, models.Session{ID: "s-keep", ProjectID: pid, Tool: models.ToolCodex, StartedAt: ended.Add(-time.Hour), EndedAt: ended}); err != nil {
		t.Fatal(err)
	}
	prompt := models.ToolEvent{
		SessionID: "s-keep", ProjectRoot: root, Timestamp: ended.Add(time.Hour), Tool: models.ToolCodex,
		SourceFile: "f", SourceEventID: "p1", ActionType: models.ActionUserPrompt, Success: true,
	}
	if _, err := st.Ingest(ctx, []models.ToolEvent{prompt}, nil, IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	var v sql.NullString
	if err := db.QueryRow(`SELECT ended_at FROM sessions WHERE id = 's-keep'`).Scan(&v); err != nil {
		t.Fatal(err)
	}
	if !v.Valid {
		t.Fatal("ended_at cleared for a session with no session_end row")
	}
}
