package watcher

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestIngestProcessResultRecordsToolAccounts pins the watcher half of the
// adapter tool-account seam: ParseResult.ToolAccounts reaches
// tool_account_observations through store.IngestOptions.ToolAccounts (the
// same writer hook-time capture uses), an account-level observation keeps
// its marker, and an account-level row that names a person is dropped.
func TestIngestProcessResultRecordsToolAccounts(t *testing.T) {
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "w.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	s := store.New(database)

	root := t.TempDir()
	at := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	obs := func(id, scope, accountID, email string) models.ToolAccountObservation {
		return models.ToolAccountObservation{
			SessionID: "s1", Tool: models.ToolAutohand, BindingKind: "message", BindingID: id,
			Role: "user", AccountID: accountID, Email: email, Source: "autohand_account_snapshot",
			Scope: scope, Stage: "activity", ObservedAt: at,
		}
	}
	stub := &stubRetryAdapter{name: "stub", root: root}
	reg := adapter.NewRegistry()
	reg.Register(stub)
	w := New(s, reg, Options{Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))})

	res := adapter.ParseResult{ToolAccounts: []models.ToolAccountObservation{
		obs("m1", models.ToolAccountScopeAccount+":device", "acct-123", ""),
		obs("m2", models.ToolAccountScopeAccount, "acct-123", "person@example.invalid"), // refused
	}}
	if err := w.ingestProcessResult(ctx, stub, res); err != nil {
		t.Fatal(err)
	}
	accounts, err := s.LoadMessageAccounts(ctx, "s1", models.ToolAutohand)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := accounts["user:m1"]
	if !ok || len(got.Evidence) != 1 {
		t.Fatalf("account-level observation not recorded: %+v", accounts)
	}
	ev := got.Evidence[0]
	if ev.AccountID != "acct-123" || ev.Email != "" || !models.ToolAccountScopeIsAccountLevel(ev.Scope) {
		t.Fatalf("evidence = %+v, want account-level acct-123 with no person field", ev)
	}
	if _, bad := accounts["user:m2"]; bad {
		t.Fatalf("account-level row naming a person was stored: %+v", accounts["user:m2"])
	}
}
