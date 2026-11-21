package store

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

func TestLoadMeToolAccounts(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 9, 10, 1, 0, 0, 0, time.UTC)
	obs := func(session, tool, id, email, stage string, at time.Time) models.ToolAccountObservation {
		return models.ToolAccountObservation{SessionID: session, Tool: tool, BindingKind: "message", BindingID: id, Role: "assistant", Email: email, Source: "cursor_hook_user_email", Scope: "native_hook", Stage: stage, ObservedAt: at}
	}
	in := []models.ToolAccountObservation{
		obs("s1", models.ToolCursor, "m1", "a@example.invalid", "activity", base),
		obs("s2", models.ToolCursor, "m2", "a@example.invalid", "activity", base.Add(time.Hour)),
		obs("s3", models.ToolCursor, "m3", "b@example.invalid", "activity", base.Add(2*time.Hour)),
		obs("s4", models.ToolCursor, "m4", "stop-only@example.invalid", "stop", base),
		obs("s5", models.ToolCodex, "m5", "c@example.invalid", "activity", base),
	}
	if _, err := s.Ingest(ctx, nil, nil, IngestOptions{ToolAccounts: in}); err != nil {
		t.Fatal(err)
	}
	got, err := s.LoadMeToolAccounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Tool != models.ToolCodex || got[1].Tool != models.ToolCursor {
		t.Fatalf("tools = %+v", got)
	}
	if got[0].Multiple || len(got[0].Accounts) != 1 {
		t.Errorf("codex should have one account: %+v", got[0])
	}
	cur := got[1]
	if !cur.Multiple || len(cur.Accounts) != 2 {
		t.Fatalf("cursor accounts = %+v", cur)
	}
	// Most recently seen first, stop-only account left out.
	if cur.Accounts[0].Email != "b@example.invalid" || cur.Accounts[1].Email != "a@example.invalid" {
		t.Errorf("order = %+v", cur.Accounts)
	}
	if a := cur.Accounts[1]; a.Sessions != 2 || a.FirstSeen >= a.LastSeen {
		t.Errorf("a = %+v", a)
	}
	// The short key is at most 8 characters and tells the two accounts apart.
	k0, k1 := cur.Accounts[0].Key, cur.Accounts[1].Key
	if k0 == "" || len(k0) > 8 || len(k1) > 8 || k0 == k1 {
		t.Errorf("keys = %q, %q", k0, k1)
	}
}

func TestLoadMeToolAccountsEmpty(t *testing.T) {
	s, _ := newTestStore(t)
	got, err := s.LoadMeToolAccounts(context.Background())
	if err != nil || len(got) != 0 {
		t.Fatalf("got %v, %v", got, err)
	}
}
