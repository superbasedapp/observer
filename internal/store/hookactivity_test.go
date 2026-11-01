package store

import (
	"context"
	"reflect"
	"testing"
	"time"
)

// TestUpsertHookActivity pins the one writer: counts add across calls and
// within one call, first_at keeps the earliest and last_at the latest, the
// latest invocation's env classes win, the unattributed bucket is its own
// row, and a row with no tool or event is skipped.
func TestUpsertHookActivity(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC)
	first := []HookActivityRow{
		{Tool: "claude-code", Event: "PreToolUse", SessionID: "s1", FirstAt: t0.Add(time.Minute), LastAt: t0.Add(time.Minute), EnvClasses: map[string]string{"ANTHROPIC_BASE_URL": "loopback"}},
		{Tool: "claude-code", Event: "PreToolUse", SessionID: "s1", FirstAt: t0, LastAt: t0},
		{Tool: "claude-code", Event: "PreToolUse", FirstAt: t0, LastAt: t0},
		{Tool: "", Event: "PreToolUse", SessionID: "s1", LastAt: t0},
		{Tool: "claude-code", Event: "", SessionID: "s1", LastAt: t0},
	}
	if err := s.UpsertHookActivity(ctx, first); err != nil {
		t.Fatal(err)
	}
	second := []HookActivityRow{
		{Tool: "claude-code", Event: "PreToolUse", SessionID: "s1", Count: 3, FirstAt: t0.Add(time.Hour), LastAt: t0.Add(time.Hour), EnvClasses: map[string]string{"ANTHROPIC_BASE_URL": "provider_direct"}},
		{Tool: "claude-code", Event: "PreToolUse", SessionID: "s1", LastAt: t0.Add(30 * time.Minute), EnvClasses: map[string]string{"ANTHROPIC_BASE_URL": "other_host"}},
	}
	if err := s.UpsertHookActivity(ctx, second); err != nil {
		t.Fatal(err)
	}
	got, err := s.LoadHookActivity(ctx, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	want := []HookActivityRow{
		{Tool: "claude-code", Event: "PreToolUse", SessionID: "", Count: 1, FirstAt: t0, LastAt: t0},
		{Tool: "claude-code", Event: "PreToolUse", SessionID: "s1", Count: 6, FirstAt: t0, LastAt: t0.Add(time.Hour), EnvClasses: map[string]string{"ANTHROPIC_BASE_URL": "provider_direct"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rows:\n got %+v\nwant %+v", got, want)
	}
	epoch, err := s.HookActivityEpoch(ctx)
	if err != nil || !epoch.Equal(t0) {
		t.Fatalf("epoch %v err %v", epoch, err)
	}
	n, err := s.PruneHookActivity(ctx, t0.Add(time.Minute))
	if err != nil || n != 1 {
		t.Fatalf("prune removed %d err %v, want the unattributed row", n, err)
	}
	if rows, _ := s.LoadHookActivity(ctx, t0.Add(2*time.Hour)); len(rows) != 0 {
		t.Fatalf("since filter: %+v", rows)
	}
}

func TestHookActivityEpochEmpty(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	if e, err := s.HookActivityEpoch(context.Background()); err != nil || !e.IsZero() {
		t.Fatalf("epoch %v err %v", e, err)
	}
}

func TestHookLivenessSessions(t *testing.T) {
	t.Parallel()
	s, database := newTestStore(t)
	ctx := context.Background()
	pid, err := s.UpsertProject(ctx, "/tmp/p", "")
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC)
	for i, r := range []struct{ id, tool, surface string }{
		{"a", "claude-code", "cli"}, {"b", "claude-code", ""}, {"c", "codex", "ide"}, {"old", "codex", "cli"},
	} {
		at := t0.Add(time.Duration(i) * time.Minute)
		if r.id == "old" {
			at = t0.Add(-48 * time.Hour)
		}
		if _, err := database.ExecContext(ctx, `INSERT INTO sessions (id, project_id, tool, started_at, surface) VALUES (?, ?, ?, ?, NULLIF(?, ''))`,
			r.id, pid, r.tool, at.Format(time.RFC3339Nano), r.surface); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.HookLivenessSessions(ctx, t0.Add(-time.Hour), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(got["claude-code"]) != 1 || got["claude-code"][0].ID != "b" || got["claude-code"][0].Surface != "" {
		t.Fatalf("claude-code: %+v", got["claude-code"])
	}
	if len(got["codex"]) != 1 || got["codex"][0].ID != "c" || got["codex"][0].Surface != "ide" || !got["codex"][0].StartedAt.Equal(t0.Add(2*time.Minute)) {
		t.Fatalf("codex: %+v", got["codex"])
	}
}
