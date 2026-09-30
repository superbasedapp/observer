package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/commitlog"
)

func mkCommit(sha string, committedAt time.Time, subject string, files []commitlog.CommitFile) commitlog.Commit {
	return commitlog.Commit{
		SHA:         sha,
		Parents:     []string{"parent1"},
		AuthorHash:  "abc123def4567890",
		AuthoredAt:  committedAt,
		CommittedAt: committedAt,
		Subject:     subject,
		IsMerge:     false,
		Files:       files,
	}
}

func TestUpsertCommitsInsertsAndCountsOnlyNew(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	projectID, err := s.UpsertProject(ctx, "/repo/one", "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}

	base := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	commits := []commitlog.Commit{
		mkCommit("sha1", base, "fix: bug", []commitlog.CommitFile{
			{RelPath: "a.go", PathHash: "hasha", Added: 3, Deleted: 1},
		}),
		mkCommit("sha2", base.Add(time.Hour), "feat: thing", []commitlog.CommitFile{
			{RelPath: "b.go", PathHash: "hashb", Added: 10, Deleted: 0},
		}),
	}

	inserted, err := s.UpsertCommits(ctx, projectID, commits, base.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("UpsertCommits: %v", err)
	}
	if inserted != 2 {
		t.Fatalf("inserted = %d, want 2", inserted)
	}

	// Re-run with an OVERLAPPING batch (sha2 again + a genuinely new sha3) —
	// the scanner's watermark-overlap shape. Only sha3 should count as new.
	commits2 := []commitlog.Commit{
		commits[1], // sha2, unchanged
		mkCommit("sha3", base.Add(2*time.Hour), "chore: tidy", nil),
	}
	inserted2, err := s.UpsertCommits(ctx, projectID, commits2, base.Add(3*time.Hour))
	if err != nil {
		t.Fatalf("UpsertCommits (overlap): %v", err)
	}
	if inserted2 != 1 {
		t.Fatalf("inserted2 = %d, want 1 (only sha3 is new)", inserted2)
	}

	rows, err := s.LoadProjectCommits(ctx, projectID, base.Add(-time.Hour), base.Add(24*time.Hour), 0)
	if err != nil {
		t.Fatalf("LoadProjectCommits: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("LoadProjectCommits returned %d rows, want 3", len(rows))
	}
	// Newest first.
	if rows[0].SHA != "sha3" || rows[len(rows)-1].SHA != "sha1" {
		t.Errorf("commits not ordered newest-first: got shas %v", []string{rows[0].SHA, rows[1].SHA, rows[2].SHA})
	}
	for _, r := range rows {
		if !r.Reachable {
			t.Errorf("commit %s not reachable by default", r.SHA)
		}
		if len(r.Parents) != 1 || r.Parents[0] != "parent1" {
			t.Errorf("commit %s parents = %v, want [parent1]", r.SHA, r.Parents)
		}
	}

	files, err := s.LoadCommitFiles(ctx, projectID, base.Add(-time.Hour), base.Add(24*time.Hour), 0)
	if err != nil {
		t.Fatalf("LoadCommitFiles: %v", err)
	}
	if len(files) != 2 { // sha1 + sha2 each carry one file; sha3 carries none
		t.Fatalf("LoadCommitFiles returned %d rows, want 2", len(files))
	}
}

// TestUpsertCommitsReplacesFilesOnReparse pins the "files rows replaced per
// commit" contract: re-upserting the SAME sha with a different file list
// (e.g. a fuller backfill re-parse after a capped periodic scan) replaces
// the stored file rows rather than appending to them.
func TestUpsertCommitsReplacesFilesOnReparse(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	projectID, err := s.UpsertProject(ctx, "/repo/reparse", "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	at := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)

	if _, err := s.UpsertCommits(ctx, projectID, []commitlog.Commit{
		mkCommit("sha1", at, "first pass", []commitlog.CommitFile{{RelPath: "a.go", PathHash: "ha"}}),
	}, at); err != nil {
		t.Fatalf("UpsertCommits (1): %v", err)
	}

	inserted, err := s.UpsertCommits(ctx, projectID, []commitlog.Commit{
		mkCommit("sha1", at, "first pass", []commitlog.CommitFile{
			{RelPath: "a.go", PathHash: "ha"},
			{RelPath: "b.go", PathHash: "hb"},
		}),
	}, at.Add(time.Minute))
	if err != nil {
		t.Fatalf("UpsertCommits (2): %v", err)
	}
	if inserted != 0 {
		t.Errorf("inserted = %d on a re-parse of an existing sha, want 0", inserted)
	}

	files, err := s.LoadCommitFiles(ctx, projectID, at.Add(-time.Hour), at.Add(time.Hour), 0)
	if err != nil {
		t.Fatalf("LoadCommitFiles: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("LoadCommitFiles returned %d rows after reparse, want 2 (replaced, not appended)", len(files))
	}
}

// TestUpsertCommitsScrubsSubject pins the store-seam scrub rule
// (docs/plans/projects-page-roi-and-commit-alignment-plan-2026-09-21.md
// §3.1: "Subject is scrubbed with internal/scrub by the STORE seam before
// insert — the pure package stays free of scrub").
func TestUpsertCommitsScrubsSubject(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	projectID, err := s.UpsertProject(ctx, "/repo/secret", "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	at := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	secret := "AKIAABCDEFGHIJKLMNOP"
	if _, err := s.UpsertCommits(ctx, projectID, []commitlog.Commit{
		mkCommit("sha1", at, "chore: rotate "+secret, nil),
	}, at); err != nil {
		t.Fatalf("UpsertCommits: %v", err)
	}

	rows, err := s.LoadProjectCommits(ctx, projectID, at.Add(-time.Hour), at.Add(time.Hour), 0)
	if err != nil {
		t.Fatalf("LoadProjectCommits: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	if subject := rows[0].Subject; strings.Contains(subject, secret) {
		t.Errorf("subject %q still carries the raw secret — scrub did not run", subject)
	}
	if !strings.Contains(rows[0].Subject, "[REDACTED]") {
		t.Errorf("subject %q does not carry the redaction marker", rows[0].Subject)
	}
}

func TestMarkCommitsReachability(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	projectID, err := s.UpsertProject(ctx, "/repo/reach", "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	at := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	if _, err := s.UpsertCommits(ctx, projectID, []commitlog.Commit{
		mkCommit("sha1", at, "a", nil),
		mkCommit("sha2", at.Add(time.Hour), "b", nil),
	}, at); err != nil {
		t.Fatalf("UpsertCommits: %v", err)
	}

	// sha2 fell out of HEAD's history (rebase/force-push) — only sha1 is
	// still reachable.
	if err := s.MarkCommitsReachability(ctx, projectID, map[string]bool{"sha1": true}, at.Add(-time.Hour)); err != nil {
		t.Fatalf("MarkCommitsReachability: %v", err)
	}
	rows, err := s.LoadProjectCommits(ctx, projectID, at.Add(-time.Hour), at.Add(24*time.Hour), 0)
	if err != nil {
		t.Fatalf("LoadProjectCommits: %v", err)
	}
	byName := map[string]ProjectCommitRow{}
	for _, r := range rows {
		byName[r.SHA] = r
	}
	if !byName["sha1"].Reachable {
		t.Error("sha1 should still be reachable")
	}
	if byName["sha2"].Reachable {
		t.Error("sha2 should have been flagged unreachable")
	}
	if len(rows) != 2 {
		t.Errorf("MarkCommitsReachability deleted a row — it must only flip the flag, never remove one; got %d rows", len(rows))
	}

	// sha2 comes back (e.g. the branch was restored) — reachable flips back
	// to true.
	if err := s.MarkCommitsReachability(ctx, projectID, map[string]bool{"sha1": true, "sha2": true}, at.Add(-time.Hour)); err != nil {
		t.Fatalf("MarkCommitsReachability (restore): %v", err)
	}
	rows, err = s.LoadProjectCommits(ctx, projectID, at.Add(-time.Hour), at.Add(24*time.Hour), 0)
	if err != nil {
		t.Fatalf("LoadProjectCommits: %v", err)
	}
	for _, r := range rows {
		if !r.Reachable {
			t.Errorf("commit %s should be reachable again after restore", r.SHA)
		}
	}
}

func TestCommitScanStateRoundTrip(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	projectID, err := s.UpsertProject(ctx, "/repo/scan", "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}

	if _, ok, err := s.CommitScanState(ctx, projectID); err != nil || ok {
		t.Fatalf("CommitScanState on a fresh project: ok=%v err=%v, want ok=false err=nil", ok, err)
	}
	if state, err := s.CommitCaptureState(ctx, projectID); err != nil || state != "never_scanned" {
		t.Fatalf("CommitCaptureState = %q, %v, want never_scanned", state, err)
	}

	now := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
	want := ScanState{
		ProjectID:           projectID,
		LastSHA:             "sha9",
		LastCommittedAt:     now.Add(-time.Hour),
		LastScanAt:          now,
		LastError:           "",
		ConsecutiveFailures: 0,
	}
	if err := s.SetCommitScanState(ctx, want); err != nil {
		t.Fatalf("SetCommitScanState: %v", err)
	}
	got, ok, err := s.CommitScanState(ctx, projectID)
	if err != nil || !ok {
		t.Fatalf("CommitScanState: ok=%v err=%v", ok, err)
	}
	if got.LastSHA != want.LastSHA || !got.LastCommittedAt.Equal(want.LastCommittedAt) || !got.LastScanAt.Equal(want.LastScanAt) {
		t.Errorf("CommitScanState round-trip = %+v, want %+v", got, want)
	}
	if state, err := s.CommitCaptureState(ctx, projectID); err != nil || state != "ok" {
		t.Fatalf("CommitCaptureState = %q, %v, want ok", state, err)
	}

	// Overwrite with a git-unavailable failure.
	want.LastError = "git not found on PATH"
	want.ConsecutiveFailures = 1
	if err := s.SetCommitScanState(ctx, want); err != nil {
		t.Fatalf("SetCommitScanState (failure): %v", err)
	}
	if state, err := s.CommitCaptureState(ctx, projectID); err != nil || state != "no_git" {
		t.Fatalf("CommitCaptureState = %q, %v, want no_git", state, err)
	}
}

func TestActiveProjectRoots(t *testing.T) {
	t.Parallel()
	s, database := newTestStore(t)
	ctx := context.Background()

	activeID, err := s.UpsertProject(ctx, "/repo/active", "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	staleID, err := s.UpsertProject(ctx, "/repo/stale", "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}

	insertSession := func(id string, projectID int64, startedAt time.Time) {
		if _, err := database.ExecContext(ctx,
			`INSERT INTO sessions (id, project_id, tool, started_at) VALUES (?, ?, 'claude-code', ?)`,
			id, projectID, startedAt.Format(time.RFC3339Nano)); err != nil {
			t.Fatalf("insert session %s: %v", id, err)
		}
	}
	insertSession("s-active", activeID, time.Now().Add(-2*24*time.Hour))
	insertSession("s-stale", staleID, time.Now().Add(-90*24*time.Hour))

	roots, err := s.ActiveProjectRoots(ctx, 30)
	if err != nil {
		t.Fatalf("ActiveProjectRoots: %v", err)
	}
	if len(roots) != 1 || roots[0].RootPath != "/repo/active" {
		t.Fatalf("ActiveProjectRoots(30) = %+v, want just /repo/active", roots)
	}

	all, err := s.ActiveProjectRoots(ctx, 0)
	if err != nil {
		t.Fatalf("ActiveProjectRoots(0): %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("ActiveProjectRoots(0) = %d roots, want 2 (no bound)", len(all))
	}
}

// TestMarkCommitsReachability_ZeroSinceIsUnbounded pins the sub-project
// self-heal contract (SOL-F15): a zero `since` revalidates EVERY stored
// row, including one committed years ago. Without the explicit branch the
// shared timestamp() helper turns a zero time into "now" and the query
// matches nothing - the regression the first F15 fix shipped with.
func TestMarkCommitsReachability_ZeroSinceIsUnbounded(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	projectID, err := s.UpsertProject(ctx, "/repo/reach-unbounded", "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	old := time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, err := s.UpsertCommits(ctx, projectID, []commitlog.Commit{
		mkCommit("old1", old, "ancient whole-repo row", nil),
		mkCommit("old2", old.Add(time.Hour), "ancient, still in subtree history", nil),
	}, old); err != nil {
		t.Fatalf("UpsertCommits: %v", err)
	}
	if err := s.MarkCommitsReachability(ctx, projectID, map[string]bool{"old2": true}, time.Time{}); err != nil {
		t.Fatalf("MarkCommitsReachability: %v", err)
	}
	rows, err := s.LoadProjectCommits(ctx, projectID, old.Add(-time.Hour), old.Add(24*time.Hour), 0)
	if err != nil {
		t.Fatalf("LoadProjectCommits: %v", err)
	}
	got := map[string]bool{}
	for _, r := range rows {
		got[r.SHA] = r.Reachable
	}
	if got["old1"] {
		t.Error("old1 fell out of the subtree history and must be flagged unreachable even though it is older than any lookback window")
	}
	if !got["old2"] {
		t.Error("old2 is still reachable and must stay reachable=1")
	}
}
