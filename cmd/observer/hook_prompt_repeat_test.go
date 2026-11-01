package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestPromptOccurrenceIDRules: one row per decision of promptOccurrenceID.
func TestPromptOccurrenceIDRules(t *testing.T) {
	now := time.Date(2026, 10, 24, 20, 39, 56, 0, time.UTC)
	const base = "s1:user_prompt_submit:abc"
	cases := []struct {
		name   string
		stored []store.HookOccurrence
		want   string
	}{
		{"new prompt in the session", nil, base},
		{"re-delivery a moment later", []store.HookOccurrence{{ID: base, At: now.Add(-time.Second)}}, base},
		{"re-delivery of the second occurrence", []store.HookOccurrence{{ID: base + "#2", At: now.Add(-2 * time.Second)}, {ID: base, At: now.Add(-10 * time.Minute)}}, base + "#2"},
		{"a row stamped later than now (clock step) is the same event", []store.HookOccurrence{{ID: base, At: now.Add(time.Second)}}, base},
		{"the same text typed again later", []store.HookOccurrence{{ID: base, At: now.Add(-10 * time.Minute)}}, base + "#2"},
		{"and a third time", []store.HookOccurrence{{ID: base + "#2", At: now.Add(-time.Minute)}, {ID: base, At: now.Add(-10 * time.Minute)}}, base + "#3"},
	}
	for _, c := range cases {
		if got := promptOccurrenceID(base, c.stored, now, promptRedeliveryWindow); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

// TestRepeatedPromptGetsItsOwnRow (Windows 11 Pro live run, B7): the same
// prompt in the same session typed twice, ten minutes apart, is two actions
// rows; the same event delivered twice (a second hook registration, a
// retry) is one. Before, the content-hash id made the second typing a
// silent upsert into the first row.
func TestRepeatedPromptGetsItsOwnRow(t *testing.T) {
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "obs.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer database.Close()
	st := store.New(database)
	body := []byte(`{"session_id":"sbo-win3","cwd":"/work","hook_event_name":"UserPromptSubmit","prompt":"sbo live check win3"}`)
	count := func() int {
		t.Helper()
		var n int
		if err := database.QueryRow(`SELECT COUNT(*) FROM actions WHERE action_type = ?`, models.ActionUserPrompt).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	deliver := func(at time.Time) {
		t.Helper()
		ev, ok := buildClaudeUserPromptSubmitEvent(body)
		if !ok {
			t.Fatal("builder refused the payload")
		}
		ev.Timestamp = at
		ev.SourceEventID = resolvePromptOccurrence(ctx, st, ev.SourceFile, ev.SourceEventID, at)
		if _, err := st.Ingest(ctx, []models.ToolEvent{ev}, nil, store.IngestOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	t0 := time.Date(2026, 10, 24, 20, 29, 26, 0, time.UTC)
	deliver(t0)
	deliver(t0.Add(300 * time.Millisecond)) // the same event again
	if n := count(); n != 1 {
		t.Fatalf("a re-delivered event made %d rows, want 1", n)
	}
	t1 := t0.Add(10 * time.Minute)
	deliver(t1) // the user types the same prompt again
	if n := count(); n != 2 {
		t.Fatalf("the same prompt typed again made %d rows in all, want 2", n)
	}
	deliver(t1.Add(time.Second)) // and that one re-delivered
	if n := count(); n != 2 {
		t.Fatalf("a re-delivery of the second prompt made %d rows in all, want 2", n)
	}
}
