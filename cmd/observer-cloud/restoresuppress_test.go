package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudtestpg"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/deletionjournal"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// TestRestoreSuppressRequiresYes proves the verb refuses to run without
// --yes, and that the check runs BEFORE the database is even opened (a bad
// DSN must not be reached) — same discipline as
// TestKillSwitchSetRequiresYes.
func TestRestoreSuppressRequiresYes(t *testing.T) {
	t.Setenv("SBCI_PG_DSN", "postgres://invalid:1/none?sslmode=disable")
	cmd := newRestoreSuppressCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(nil)
	err := cmd.Execute()
	if err == nil {
		t.Fatal("restore-suppress ran without --yes")
	}
	if !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("refusal must name --yes: %v", err)
	}
	if strings.Contains(err.Error(), "connect") || strings.Contains(err.Error(), "dial") {
		t.Fatalf("the --yes check must run BEFORE the database is opened: %v", err)
	}
}

// TestRestoreSuppressTopLevelHasYesFlag pins the flag shape so a future
// refactor can't silently drop the confirmation gate.
func TestRestoreSuppressTopLevelHasYesFlag(t *testing.T) {
	cmd := newRestoreSuppressCmd()
	if fl := cmd.Flags().Lookup("yes"); fl == nil {
		t.Fatal("restore-suppress must have a --yes flag")
	}
}

// TestRestoreSuppressEmptyJournalAgainstThrowawayPG exercises the exact store
// seam the CLI's RunE calls (SuppressFromJournal,
// internal/cloudserver/store/deletion.go) against a throwaway, freshly-
// migrated Postgres — the D "store test against the throwaway PG"
// requirement. An empty deletion journal suppresses zero accounts and must
// not error (mirrors TestKillSwitchEndToEndAgainstThrowawayPG's shape: call
// the store directly via store.New(pool) rather than round-tripping a DSN
// through the CLI's own env-var plumbing, which cloudtestpg's per-test
// database has no reusable DSN accessor for). Skips gracefully when
// SBCI_TEST_PG_DSN is unset (cloudtestpg.NewDB).
func TestRestoreSuppressEmptyJournalAgainstThrowawayPG(t *testing.T) {
	pool := cloudtestpg.NewDB(t)
	s := store.New(pool)

	journal, err := deletionjournal.NewFileJournal(filepath.Join(t.TempDir(), "deletion-journal.jsonl"))
	if err != nil {
		t.Fatalf("NewFileJournal: %v", err)
	}
	s.SetDeletionJournal(journal)

	n, err := s.SuppressFromJournal(t.Context(), time.Now())
	if err != nil {
		t.Fatalf("SuppressFromJournal (empty journal): %v", err)
	}
	if n != 0 {
		t.Fatalf("suppressed=%d on an empty journal, want 0", n)
	}
}

// TestRestoreSuppressNoJournalConfiguredErrors proves the store refuses (not
// panics) when no deletion journal has been wired — the same fail-closed
// shape SuppressFromJournal documents, and the reason openStore's automatic
// journal wiring (cmd/observer-cloud/main.go::openStoreForRole) matters: a
// misconfigured deployment must get a clear error, not silently suppress
// nothing while believing it succeeded.
func TestRestoreSuppressNoJournalConfiguredErrors(t *testing.T) {
	pool := cloudtestpg.NewDB(t)
	s := store.New(pool)

	_, err := s.SuppressFromJournal(t.Context(), time.Now())
	if err == nil {
		t.Fatal("SuppressFromJournal with no journal configured must error, not silently succeed")
	}
	if !strings.Contains(err.Error(), "no journal configured") {
		t.Fatalf("error = %v, want it to name the missing journal configuration", err)
	}
}
