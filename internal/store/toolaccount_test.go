package store

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

func TestToolAccountsSwitchReplayAndLateJoin(t *testing.T) {
	s, database := newTestStore(t)
	ctx := context.Background()
	at := time.Date(2026, 9, 10, 1, 0, 0, 0, time.UTC)
	observation := func(id, email, stage string) models.ToolAccountObservation {
		return models.ToolAccountObservation{SessionID: "accounts", Tool: models.ToolCursor, BindingKind: "message", BindingID: id, Role: "assistant", Email: email, Source: "cursor_hook_user_email", Scope: "native_hook", Stage: stage, ObservedAt: at}
	}
	first := observation("g1", "first@example.invalid", "activity")
	second := observation("g2", "second@example.invalid", "activity")
	stop := observation("g3", "second@example.invalid", "stop")
	submit := observation("user:g4", "first@example.invalid", "submission")
	submit.Role = "user"
	call := observation("call1", "first@example.invalid", "activity")
	call.BindingKind = "tool_call"
	for range 2 {
		if _, err := s.Ingest(ctx, nil, nil, IngestOptions{ToolAccounts: []models.ToolAccountObservation{first, second, stop, submit, call}}); err != nil {
			t.Fatal(err)
		}
	}
	a, err := s.LoadMessageAccounts(ctx, "accounts", models.ToolCursor)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ key, label string }{{"assistant:g1", first.Email}, {"assistant:g2", second.Email}, {"user:user:g4", submit.Email}} {
		if a[tc.key].Status != "observed" || a[tc.key].Label != tc.label || len(a[tc.key].Evidence) != 1 {
			t.Fatalf("%s: %+v", tc.key, a[tc.key])
		}
	}
	for _, key := range []string{"assistant:g3", "assistant:g4", "assistant:late"} {
		if _, ok := a[key]; ok {
			t.Fatalf("unproven binding %s", key)
		}
	}
	conflict := first
	conflict.Email = second.Email
	ev := models.ToolEvent{SessionID: "accounts", ProjectRoot: t.TempDir(), Tool: models.ToolCursor, SourceFile: "fixture", SourceEventID: "call1", MessageID: "late", ActionType: models.ActionReadFile, Timestamp: at, Success: true}
	if _, err := s.Ingest(ctx, []models.ToolEvent{ev}, nil, IngestOptions{ToolAccounts: []models.ToolAccountObservation{conflict}}); err != nil {
		t.Fatal(err)
	}
	a, err = s.LoadMessageAccounts(ctx, "accounts", models.ToolCursor)
	if err != nil {
		t.Fatal(err)
	}
	if a["assistant:g1"].Status != "conflict" || len(a["assistant:g1"].Evidence) != 2 {
		t.Fatalf("lost conflict: %+v", a)
	}
	if a["assistant:late"].Label != first.Email || a["assistant:g2"].Label != second.Email {
		t.Fatalf("late join/switch: %+v", a)
	}
	other, err := s.LoadMessageAccounts(ctx, "accounts", models.ToolClaudeCode)
	if err != nil || len(other) != 0 {
		t.Fatalf("cross-tool leak: %+v %v", other, err)
	}
	other, err = s.LoadMessageAccounts(ctx, "different", models.ToolCursor)
	if err != nil || len(other) != 0 {
		t.Fatalf("cross-session leak: %+v %v", other, err)
	}
	// A duplicate action must still accept evidence arriving later.
	conflict.BindingID = "late"
	if _, err := s.Ingest(ctx, []models.ToolEvent{ev}, nil, IngestOptions{ToolAccounts: []models.ToolAccountObservation{conflict}}); err != nil {
		t.Fatal(err)
	}
	a, err = s.LoadMessageAccounts(ctx, "accounts", models.ToolCursor)
	if err != nil || a["assistant:late"].Status != "conflict" {
		t.Fatalf("dedup lost late evidence: %+v %v", a, err)
	}
	if _, err := database.ExecContext(ctx, `DELETE FROM actions WHERE session_id='accounts'; DELETE FROM sessions WHERE id='accounts'`); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM tool_account_observations`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("delete retained identities: %d %v", count, err)
	}
}
