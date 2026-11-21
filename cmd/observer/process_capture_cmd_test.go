//go:build !sbo_omit_processobs

package main

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/proccapture"
	"github.com/marmutapp/superbased-observer/internal/procmodel"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// compactTestStore opens a fresh node database.
func compactTestStore(t *testing.T) *store.Store {
	t.Helper()
	database, err := db.Open(context.Background(), db.Options{Path: filepath.Join(t.TempDir(), "observer.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return store.New(database)
}

// seedLegacySession ingests one action for the session at `at` (so the
// session row exists and its last activity is known) and stores a legacy,
// pre-budget process tree under it: a seed root, a tool-call shell, n short
// successful git children, one failed child and one child running from /tmp
// (a finding). Every run is seen last at `at` + a few seconds.
func seedLegacySession(t *testing.T, st *store.Store, sess string, at time.Time, n int) {
	t.Helper()
	ctx := context.Background()
	if _, err := st.Ingest(ctx, []models.ToolEvent{{
		SourceFile: "f-" + sess, SourceEventID: "e-" + sess, SessionID: sess,
		ProjectRoot: t.TempDir(), Timestamp: at, Tool: models.ToolClaudeCode,
		ActionType: models.ActionReadFile, Target: "a.go", Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	mk := func(key, parent, exe string, i int) procmodel.ProcessRun {
		started := at.Add(time.Duration(i) * 20 * time.Millisecond)
		src := procmodel.AttrInherited
		if parent == "" {
			src = procmodel.AttrBridge
		}
		return procmodel.ProcessRun{
			ProcessKey: sess + "-" + key, ParentProcessKey: parentKey(sess, parent), BootID: "b", PID: 1000 + i,
			StartTimeTicks: int64(1000 + i),
			Attribution:    procmodel.Attribution{SessionID: sess, Tool: "claude-code", Source: src, Confidence: procmodel.ConfHigh},
			ExePath:        "/usr/bin/" + exe, ExeBasename: exe, ArgvPreview: exe + " status", UID: 1000, EUID: 1000,
			StartedAt: started, LastSeenAt: started.Add(10 * time.Millisecond),
			Exited: true, ExitedAt: started.Add(10 * time.Millisecond), DurationMs: 10,
		}
	}
	runs := []procmodel.ProcessRun{mk("root", "", "claude", 0), mk("sh", "root", "bash", 1)}
	for i := range n {
		runs = append(runs, mk(fmt.Sprintf("git-%03d", i), "sh", "git", i+2))
	}
	failed := mk("failed", "sh", "git", n+2)
	failed.ExitCode = 1
	finding := mk("tmp", "sh", "payload", n+3)
	finding.ExePath = "/tmp/payload"
	runs = append(runs, failed, finding)
	if _, err := st.PersistRuns(ctx, runs); err != nil {
		t.Fatalf("PersistRuns: %v", err)
	}
}

func parentKey(sess, parent string) string {
	if parent == "" {
		return ""
	}
	return sess + "-" + parent
}

func compactCfg() proccapture.Config {
	cfg := proccapture.DefaultConfig()
	cfg.PerToolCall = 25
	return cfg
}

func sessionRowCount(t *testing.T, st *store.Store, sess string) int64 {
	t.Helper()
	n, _, err := st.ProcessSessionRowMark(context.Background(), sess)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// TestProcessCompactDryRunWritesNothing: a dry run prints the plan and
// leaves every row, and the absent stats row, as they were.
func TestProcessCompactDryRunWritesNothing(t *testing.T) {
	st := compactTestStore(t)
	now := time.Now().UTC()
	seedLegacySession(t, st, "old", now.Add(-3*time.Hour), 100)
	before := sessionRowCount(t, st, "old")

	var out strings.Builder
	sum, err := runProcessCompact(context.Background(), st, compactCfg(), processCompactOptions{DryRun: true, Now: now}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Compacted != 1 || sum.RowsAfter >= sum.RowsBefore {
		t.Fatalf("dry-run summary %+v", sum)
	}
	if got := sessionRowCount(t, st, "old"); got != before {
		t.Fatalf("dry run deleted rows: %d -> %d", before, got)
	}
	if _, ok, _ := st.ProcessCaptureStatsForSession(context.Background(), "old"); ok {
		t.Fatal("dry run wrote a stats row")
	}
	if n, _ := st.ProcessRollupRowCount(context.Background(), "old"); n != 0 {
		t.Fatalf("dry run wrote %d rollup rows", n)
	}
	if !strings.Contains(out.String(), "dry run: nothing was written") {
		t.Fatalf("output:\n%s", out.String())
	}
}

// TestProcessCompactKeepsProtectedRowsAndInvariant: a real compaction keeps
// the seed root, the tool-call shell, the failure and the finding, and the
// session's stats satisfy the count invariant over the original row count;
// an active session is skipped untouched; a second run changes nothing.
func TestProcessCompactKeepsProtectedRowsAndInvariant(t *testing.T) {
	st := compactTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	seedLegacySession(t, st, "old", now.Add(-3*time.Hour), 100)
	seedLegacySession(t, st, "live", now.Add(-time.Minute), 100)
	oldBefore, liveBefore := sessionRowCount(t, st, "old"), sessionRowCount(t, st, "live")

	var out strings.Builder
	sum, err := runProcessCompact(ctx, st, compactCfg(), processCompactOptions{Now: now}, &out)
	if err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if sum.Compacted != 1 || sum.SkippedActive != 1 {
		t.Fatalf("summary %+v\n%s", sum, out.String())
	}
	if got := sessionRowCount(t, st, "live"); got != liveBefore {
		t.Fatalf("active session was compacted: %d -> %d", liveBefore, got)
	}
	runs, err := st.ProcessRunsForSession(ctx, "old")
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(runs)) >= oldBefore {
		t.Fatalf("nothing compacted: %d rows", len(runs))
	}
	have := map[string]bool{}
	for _, r := range runs {
		have[r.ProcessKey] = true
	}
	for _, k := range []string{"old-root", "old-sh", "old-failed", "old-tmp"} {
		if !have[k] {
			t.Fatalf("protected row %s deleted", k)
		}
	}
	stats, ok, err := st.ProcessCaptureStatsForSession(ctx, "old")
	if err != nil || !ok {
		t.Fatalf("stats %v %v", ok, err)
	}
	if stats.Observed != oldBefore || stats.Observed != stats.Accounted() {
		t.Fatalf("count invariant: %+v over %d stored rows", stats, oldBefore)
	}
	if stats.Kept+stats.ServiceKept != int64(len(runs)) {
		t.Fatalf("stats kept %d+%d, rows %d", stats.Kept, stats.ServiceKept, len(runs))
	}
	if !strings.Contains(out.String(), "skipped, active") {
		t.Fatalf("output does not report the active session:\n%s", out.String())
	}

	// Stats agrees with what compact did, and a second compaction is a no-op.
	rep, err := buildProcessStats(ctx, st, compactCfg(), "old", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Sessions) != 1 || rep.Sessions[0].Legacy || rep.Sessions[0].IfReplayed == nil || rep.Sessions[0].IfReplayed.RowsRemoved != 0 {
		t.Fatalf("stats after compaction %+v", rep.Sessions)
	}
	out.Reset()
	again, err := runProcessCompact(ctx, st, compactCfg(), processCompactOptions{SessionID: "old", Now: now}, &out)
	if err != nil || again.Compacted != 0 || again.Unchanged != 1 {
		t.Fatalf("second run %+v %v\n%s", again, err, out.String())
	}
}

// TestProcessCompactBeforeAndDisabled: --before limits the sessions; a
// disabled capture budget refuses.
func TestProcessCompactBeforeAndDisabled(t *testing.T) {
	st := compactTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	seedLegacySession(t, st, "old", now.Add(-48*time.Hour), 60)
	seedLegacySession(t, st, "newer", now.Add(-3*time.Hour), 60)

	var out strings.Builder
	sum, err := runProcessCompact(ctx, st, compactCfg(), processCompactOptions{Before: now.Add(-24 * time.Hour), Now: now}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Compacted != 1 || sum.SkippedBefore != 1 {
		t.Fatalf("summary %+v\n%s", sum, out.String())
	}
	if _, ok, _ := st.ProcessCaptureStatsForSession(ctx, "newer"); ok {
		t.Fatal("--before compacted a later session")
	}

	off := compactCfg()
	off.Enabled = false
	if _, err := runProcessCompact(ctx, st, off, processCompactOptions{Now: now}, &out); err == nil {
		t.Fatal("compact ran with the capture limits off")
	}
	if _, err := parseCompactBefore("2026-11-01"); err != nil {
		t.Fatal(err)
	}
	if _, err := parseCompactBefore("last week"); err == nil {
		t.Fatal("a bad --before parsed")
	}
}

// TestProcessStatsLegacy: a legacy session reports its row count as kept and
// what the current limits would keep.
func TestProcessStatsLegacy(t *testing.T) {
	st := compactTestStore(t)
	ctx := context.Background()
	seedLegacySession(t, st, "old", time.Now().UTC().Add(-3*time.Hour), 80)
	rep, err := buildProcessStats(ctx, st, compactCfg(), "", defaultStatsSessions)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Sessions) != 1 {
		t.Fatalf("sessions %+v", rep.Sessions)
	}
	s := rep.Sessions[0]
	if !s.Legacy || s.Stats.Observed != s.Rows || s.Stats.Kept != s.Rows || s.BytesEstimate <= 0 {
		t.Fatalf("legacy row %+v", s)
	}
	if s.IfReplayed == nil || s.IfReplayed.RowsKept >= int(s.Rows) || s.IfReplayed.RowsRemoved == 0 ||
		s.IfReplayed.Stats.Observed != s.IfReplayed.Stats.Kept+s.IfReplayed.Stats.Folded+s.IfReplayed.Stats.RolledUp+
			s.IfReplayed.Stats.ServiceKept+s.IfReplayed.Stats.ServiceRolledUp+s.IfReplayed.Stats.Dropped {
		t.Fatalf("replay %+v", s.IfReplayed)
	}
	var out strings.Builder
	renderProcessStats(&out, rep)
	for _, want := range []string{"session old", "legacy", "under the current limits: keeps"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("stats output missing %q:\n%s", want, out.String())
		}
	}
}

// seedLiveService stores a classified service subtree under the session, its
// rows sighted at `seen`: what a Docker Desktop launched from the session's
// console leaves running long after the session itself went quiet.
func seedLiveService(t *testing.T, st *store.Store, sess string, started, seen time.Time) {
	t.Helper()
	mk := func(key, parent, class string, i int) procmodel.ProcessRun {
		return procmodel.ProcessRun{
			ProcessKey: sess + "-" + key, ParentProcessKey: parentKey(sess, parent), BootID: "b", PID: 5000 + i,
			StartTimeTicks: int64(5000 + i),
			Attribution:    procmodel.Attribution{SessionID: sess, Tool: "claude-code", Source: procmodel.AttrInherited, Confidence: procmodel.ConfHigh},
			ExePath:        "/usr/bin/" + key, ExeBasename: key, UID: 1000, EUID: 1000,
			StartedAt: started, LastSeenAt: seen,
			CaptureClass: class, ServiceRootKey: sess + "-dockerd",
		}
	}
	if _, err := st.PersistRuns(context.Background(), []procmodel.ProcessRun{
		mk("dockerd", "", "service_root", 0), mk("wsl", "dockerd", "service", 1),
	}); err != nil {
		t.Fatalf("PersistRuns: %v", err)
	}
}

// TestProcessCompactIgnoresLiveService: a session idle for hours is compacted
// even while a service it started is still being sighted, and the service
// rows survive untouched. A session with its own live row is still skipped.
func TestProcessCompactIgnoresLiveService(t *testing.T) {
	st := compactTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	seedLegacySession(t, st, "quiet", now.Add(-3*time.Hour), 100)
	seedLiveService(t, st, "quiet", now.Add(-3*time.Hour), now.Add(-5*time.Second))
	seedLegacySession(t, st, "live", now.Add(-time.Minute), 100)
	seedLiveService(t, st, "live", now.Add(-time.Minute), now.Add(-5*time.Second))
	before, liveBefore := sessionRowCount(t, st, "quiet"), sessionRowCount(t, st, "live")

	var out strings.Builder
	sum, err := runProcessCompact(ctx, st, compactCfg(), processCompactOptions{Now: now}, &out)
	if err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if sum.Compacted != 1 || sum.SkippedActive != 1 {
		t.Fatalf("summary %+v\n%s", sum, out.String())
	}
	if got := sessionRowCount(t, st, "quiet"); got >= before {
		t.Fatalf("quiet session not compacted: %d -> %d\n%s", before, got, out.String())
	}
	if got := sessionRowCount(t, st, "live"); got != liveBefore {
		t.Fatalf("active session was compacted: %d -> %d", liveBefore, got)
	}
	runs, err := st.ProcessRunsForSession(ctx, "quiet")
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, r := range runs {
		have[r.ProcessKey] = true
	}
	if !have["quiet-dockerd"] || !have["quiet-wsl"] {
		t.Fatalf("a service row was compacted away: %v", have)
	}
}
