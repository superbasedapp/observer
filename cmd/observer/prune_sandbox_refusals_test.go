package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestRunRetentionPrunesSandboxRefusals (tracker F-009, audit finding
// N1-A5): the daemon's retention pass (the startup pass and every interval
// tick) prunes the sandbox egress refusal audit past its horizon, with no
// sandbox relay running, and keeps a fresh row.
func TestRunRetentionPrunesSandboxRefusals(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "prune.db")
	database, err := dbtemplate.Open(ctx, db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	s := store.New(database)
	now := time.Now().UTC()
	for _, r := range []store.SandboxEgressRefusal{
		{RunID: "run-old", Host: "old.example", Rule: "ssrf-floor", At: now.Add(-store.SandboxEgressRefusalRetention - time.Hour)},
		{RunID: "run-new", Host: "new.example", Rule: "ssrf-floor", At: now},
	} {
		if _, err := s.InsertSandboxEgressRefusal(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	cfg := config.Default()
	cfg.Observer.DBPath = path
	if _, err := runRetention(ctx, cfg, database); err != nil {
		t.Fatal(err)
	}
	for run, want := range map[string]int{"run-old": 0, "run-new": 1} {
		rows, err := s.ListSandboxEgressRefusalsByRun(ctx, run, 0, 0)
		if err != nil || len(rows) != want {
			t.Fatalf("%s: %d rows (%v), want %d", run, len(rows), err, want)
		}
	}
}
