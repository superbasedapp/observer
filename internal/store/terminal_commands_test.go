package store

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
)

func newTermTestStore(t *testing.T) *Store {
	t.Helper()
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: t.TempDir() + "/t.db"})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return New(database)
}

func TestTerminalCommandRoundTrip(t *testing.T) {
	s := newTermTestStore(t)
	ctx := context.Background()
	code := 0
	start := time.Now().UTC().Truncate(time.Second)
	if err := s.InsertTerminalCommand(ctx, TerminalCommand{
		RunID: "run-1", TurnSeq: 1, StartedAt: start, ExitCode: &code, Trust: "hint",
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	got, err := s.LoadTerminalCommands(ctx, "run-1")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got) != 1 || got[0].TurnSeq != 1 || got[0].Trust != "hint" || got[0].ExitCode == nil || *got[0].ExitCode != 0 {
		t.Fatalf("row = %+v", got)
	}
}

func TestTerminalCommandTrustUpgrade(t *testing.T) {
	s := newTermTestStore(t)
	ctx := context.Background()
	// A hint boundary lands first.
	if err := s.InsertTerminalCommand(ctx, TerminalCommand{RunID: "r", TurnSeq: 2, Trust: "hint"}); err != nil {
		t.Fatalf("insert hint: %v", err)
	}
	// A trusted OOB confirmation for the same slot upgrades trust to oob and
	// fills the exit code, without a duplicate row.
	code := 3
	if err := s.InsertTerminalCommand(ctx, TerminalCommand{RunID: "r", TurnSeq: 2, Trust: "oob", ExitCode: &code}); err != nil {
		t.Fatalf("insert oob: %v", err)
	}
	got, err := s.LoadTerminalCommands(ctx, "r")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 row after upsert, got %d", len(got))
	}
	if got[0].Trust != "oob" || got[0].ExitCode == nil || *got[0].ExitCode != 3 {
		t.Fatalf("row not upgraded: %+v", got[0])
	}
	// The reverse (a later hint) must NOT downgrade a trusted boundary.
	if err := s.InsertTerminalCommand(ctx, TerminalCommand{RunID: "r", TurnSeq: 2, Trust: "hint"}); err != nil {
		t.Fatalf("insert hint again: %v", err)
	}
	got, _ = s.LoadTerminalCommands(ctx, "r")
	if got[0].Trust != "oob" {
		t.Fatalf("trusted boundary was downgraded to %q", got[0].Trust)
	}
}

func TestInsertTerminalCommandRequiresTrust(t *testing.T) {
	s := newTermTestStore(t)
	if err := s.InsertTerminalCommand(context.Background(), TerminalCommand{RunID: "r", TurnSeq: 1}); err == nil {
		t.Fatal("expected an error when trust is empty")
	}
}
