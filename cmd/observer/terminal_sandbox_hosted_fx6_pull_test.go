//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestHostedCaptureRunsTable pins the capture-run rule (lane FX6, F-P7-4),
// one case per row.
func TestHostedCaptureRunsTable(t *testing.T) {
	since := time.Date(2026, 4, 16, 10, 0, 2, 0, time.UTC)
	cases := []struct {
		name string
		runs hostedCaptureRuns
		at   time.Time
		want string
	}{
		{"fresh run", hostedCaptureRuns{Run: "R1", Since: since}, since.Add(-time.Hour), "R1"},
		{"resumed run, an event before its start", hostedCaptureRuns{Run: "R1", Earlier: "H", Since: since}, since.Add(-time.Second), "H"},
		{"resumed run, an event at its start", hostedCaptureRuns{Run: "R1", Earlier: "H", Since: since}, since, "R1"},
		{"resumed run, an event after its start", hostedCaptureRuns{Run: "R1", Earlier: "H", Since: since}, since.Add(time.Second), "R1"},
		{"an event with no time", hostedCaptureRuns{Run: "R1", Earlier: "H", Since: since}, time.Time{}, "R1"},
		{"no start known", hostedCaptureRuns{Run: "R1", Earlier: "H"}, since, "R1"},
		{"an earlier id that is no run id", hostedCaptureRuns{Run: "R1", Earlier: "a b/c", Since: since}, since.Add(-time.Second), "R1"},
	}
	for _, tc := range cases {
		if got := tc.runs.runFor(tc.at); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestHostedIngestKeepsTheHeldRunsCapture (lane FX6, F-P7-4): after a
// resume the held run's first session was split: its api_turns stayed
// under rsbx-<held run>-<session> (the relay stamped the run that was live)
// and its pulled actions landed under rsbx-<resumed run>-<session>. The
// resumed run's pull now re-keys the events from before its start under
// the held run, so the held run's actions, tokens and session row share
// its api_turns' id; the resumed run's own events stay under its id, and a
// later pull adds nothing.
func TestHostedIngestKeepsTheHeldRunsCapture(t *testing.T) {
	ctx := context.Background()
	d, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "o.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	src, err := os.ReadFile(filepath.Join("..", "..", "testdata", "claudecode", "simple-session.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	q := filepath.Join(t.TempDir(), "s.jsonl")
	if err := os.WriteFile(q, src, 0o600); err != nil {
		t.Fatal(err)
	}
	runs := hostedCaptureRuns{Run: "runR", Earlier: "runH", Since: time.Date(2026, 4, 16, 10, 0, 2, 0, time.UTC)}
	out, err := hostedIngestPulled(store.New(d))(ctx, "claude-code", runs, []string{q})
	if err != nil || out.Actions == 0 {
		t.Fatalf("ingested %d %v", out.Actions, err)
	}
	count := func(q string, args ...any) int {
		t.Helper()
		var n int
		if err := d.QueryRowContext(ctx, q, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	held, resumed := "rsbx-runH-sess-001", "rsbx-runR-sess-001"
	total := count(`SELECT COUNT(*) FROM actions`)
	for _, s := range []string{held, resumed} {
		if count(`SELECT COUNT(*) FROM actions WHERE session_id = ?`, s) == 0 || count(`SELECT COUNT(*) FROM sessions WHERE id = ?`, s) != 1 {
			t.Fatalf("session %s: its actions or its session row are missing", s)
		}
	}
	if count(`SELECT COUNT(*) FROM actions WHERE session_id NOT IN (?, ?)`, held, resumed) != 0 {
		t.Fatal("an action landed outside the two runs' ids")
	}
	again, err := hostedIngestPulled(store.New(d))(ctx, "claude-code", runs, []string{q})
	if err != nil || again.Actions != 0 {
		t.Fatalf("a second pull re-inserted %d (%v)", again.Actions, err)
	}
	if got := count(`SELECT COUNT(*) FROM actions`); got != total {
		t.Fatalf("actions %d after the second pull, want %d", got, total)
	}
}
