package store

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestSessionIDsActiveSince: the sessions a worker run touched are the ones
// that started in the run, plus older sessions with a proxied turn in the
// run; a session with neither is left alone, and a turn without a session
// row yields nothing (the stamp could not land on it).
func TestSessionIDsActiveSince(t *testing.T) {
	t.Parallel()
	s, db := newTestStore(t)
	ctx := context.Background()
	runStart := time.Date(2026, 11, 1, 12, 0, 0, 500_000_000, time.UTC)

	pid, _ := s.UpsertProject(ctx, "/tmp/worker", "")
	for _, sess := range []struct {
		id string
		at time.Time
	}{
		{"before-idle", runStart.Add(-time.Hour)},
		{"before-proxied", runStart.Add(-time.Hour)},
		{"same-second", runStart.Add(-200 * time.Millisecond)},
		{"during", runStart.Add(time.Minute)},
	} {
		if err := s.UpsertSession(ctx, models.Session{ID: sess.id, ProjectID: pid, Tool: models.ToolClaudeCode, StartedAt: sess.at}); err != nil {
			t.Fatal(err)
		}
	}
	insertTurn := func(sessionID string, at time.Time) {
		t.Helper()
		if _, err := db.ExecContext(ctx, `INSERT INTO api_turns (session_id, project_id, timestamp, provider, model, input_tokens, output_tokens)
			VALUES (?, ?, ?, 'anthropic', 'claude-x', 1, 1)`, sessionID, pid, at.UTC().Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
	}
	insertTurn("before-proxied", runStart.Add(2*time.Minute))
	insertTurn("before-idle", runStart.Add(-30*time.Minute))
	insertTurn("no-session-row", runStart.Add(time.Minute))

	got, err := s.SessionIDsActiveSince(ctx, runStart)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"before-proxied", "during", "same-second"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
