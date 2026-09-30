package store

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/commitlog"
	"github.com/marmutapp/superbased-observer/internal/loc"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/projectroi"
)

// ownershipFixture seeds one project with two sessions that co-contribute
// to one commit, plus a commit no AI edit reached:
//
//   - sA: prompt at base, a 3-line code edit to a.go, then an edit to
//     README.md (a docs file - a reached FILE, but zero code lines);
//   - sB: prompt at base+10m, a 1-line code edit to b.go;
//   - c1 at base+30m carries a.go, b.go and README.md -> owned by sA on
//     most_code_lines, sB a contributor;
//   - c2 at base+40m touches only notes.txt -> owner none, no_ai_edits.
func ownershipFixture(t *testing.T) (s *Store, projectID int64, base time.Time) {
	t.Helper()
	s, _ = newTestStore(t)
	ctx := context.Background()
	root := "/repo/ownership"
	base = time.Now().UTC().Add(-3 * time.Hour).Truncate(time.Second)

	events := []models.ToolEvent{
		promptEvent("sA", root, "add the parser", "pA", base),
		editEvent("sA", root, root+"/a.go", "eA1", "a := 1", `a := 2\nb := 3\nc := 4`, base.Add(time.Minute)),
		editEvent("sA", root, root+"/README.md", "eA2", "old words", `new words\nmore words`, base.Add(2*time.Minute)),
		promptEvent("sB", root, "tweak b", "pB", base.Add(10*time.Minute)),
		editEvent("sB", root, root+"/b.go", "eB1", "b := 1", "b := 2", base.Add(11*time.Minute)),
	}
	if _, err := s.Ingest(ctx, events, nil, IngestOptions{}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	var err error
	projectID, err = s.ProjectIDForRoot(ctx, root)
	if err != nil {
		t.Fatalf("ProjectIDForRoot: %v", err)
	}
	commits := []commitlog.Commit{
		{
			SHA: "c1sha", AuthorHash: "au", AuthoredAt: base.Add(30 * time.Minute), CommittedAt: base.Add(30 * time.Minute),
			Subject: "feat: parser",
			Files: []commitlog.CommitFile{
				{RelPath: "a.go", PathHash: loc.PathHash(root, root+"/a.go"), Added: 3},
				{RelPath: "b.go", PathHash: loc.PathHash(root, root+"/b.go"), Added: 1},
				{RelPath: "README.md", PathHash: loc.PathHash(root, root+"/README.md"), Added: 2},
			},
		},
		{
			SHA: "c2sha", AuthorHash: "au", AuthoredAt: base.Add(40 * time.Minute), CommittedAt: base.Add(40 * time.Minute),
			Subject: "docs: notes",
			Files:   []commitlog.CommitFile{{RelPath: "notes.txt", PathHash: loc.PathHash(root, root+"/notes.txt"), Added: 1}},
		},
	}
	if _, err := s.UpsertCommits(ctx, projectID, commits, base.Add(45*time.Minute)); err != nil {
		t.Fatalf("UpsertCommits: %v", err)
	}
	return s, projectID, base
}

func commitIDBySHA(t *testing.T, res CommitOwnershipResult, sha string) int64 {
	t.Helper()
	for _, c := range res.Commits {
		if c.SHA == sha {
			return c.ID
		}
	}
	t.Fatalf("commit %s not in result: %+v", sha, res.Commits)
	return 0
}

// TestLoadCommitOwnership pins the store composition of the ownership fold:
// the co-contributed commit is owned by the session with the most CODE
// lines (a docs file counts as a reached file, never as code lines), shares
// sum to 1 on the code-lines basis, and a commit no AI edit reached has no
// owner (reason no_ai_edits, never a guess).
func TestLoadCommitOwnership(t *testing.T) {
	t.Parallel()
	s, projectID, base := ownershipFixture(t)
	ctx := context.Background()

	res, err := s.LoadCommitOwnership(ctx, projectID, base.Add(-time.Hour), base.Add(2*time.Hour), 0, OwnershipCaps{})
	if err != nil {
		t.Fatalf("LoadCommitOwnership: %v", err)
	}
	if res.Truncated() {
		t.Errorf("Truncated() = true, want false")
	}
	if len(res.Commits) != 2 {
		t.Fatalf("commits = %d, want 2", len(res.Commits))
	}
	c1 := res.Ownership[commitIDBySHA(t, res, "c1sha")]
	if c1.OwnerSessionID != "sA" || c1.Reason != projectroi.OwnerMostCodeLines {
		t.Errorf("c1 owner = %q/%q, want sA/%s", c1.OwnerSessionID, c1.Reason, projectroi.OwnerMostCodeLines)
	}
	if c1.ShareBasis != projectroi.ShareBasisCodeLines {
		t.Errorf("c1 share basis = %q, want %q", c1.ShareBasis, projectroi.ShareBasisCodeLines)
	}
	if len(c1.Contributors) != 2 {
		t.Fatalf("c1 contributors = %+v, want 2", c1.Contributors)
	}
	var sum float64
	for _, c := range c1.Contributors {
		sum += c.Share
	}
	if math.Abs(sum-1) > 1e-9 {
		t.Errorf("c1 shares sum to %v, want 1", sum)
	}
	a := c1.Contributors[0]
	if a.SessionID != "sA" || a.Files != 2 || a.Prompts != 1 {
		t.Errorf("sA contribution = %+v, want files=2 (a.go + README.md) prompts=1", a)
	}
	b := c1.Contributors[1]
	if a.CodeLines <= b.CodeLines {
		t.Errorf("sA code lines %d <= sB %d; the README.md edit must add no code lines and a.go must outweigh b.go", a.CodeLines, b.CodeLines)
	}
	c2 := res.Ownership[commitIDBySHA(t, res, "c2sha")]
	if c2.OwnerSessionID != "" || c2.Reason != projectroi.OwnerNoneNoAIEdits || len(c2.Contributors) != 0 {
		t.Errorf("c2 ownership = %+v, want no owner, reason %s", c2, projectroi.OwnerNoneNoAIEdits)
	}

	// Caps are reported, never silent.
	capped, err := s.LoadCommitOwnership(ctx, projectID, base.Add(-time.Hour), base.Add(2*time.Hour), 0, OwnershipCaps{Commits: 1})
	if err != nil {
		t.Fatalf("LoadCommitOwnership(capped): %v", err)
	}
	if !capped.CommitsTruncated || !capped.Truncated() {
		t.Errorf("commit cap 1 over 2 commits: CommitsTruncated=%v, want true", capped.CommitsTruncated)
	}
}

// TestLoadSessionWindowAndSpan pins the session span resolution and the
// window SessionOwnershipSpan derives from it.
func TestLoadSessionWindowAndSpan(t *testing.T) {
	t.Parallel()
	s, projectID, base := ownershipFixture(t)
	ctx := context.Background()
	now := time.Now().UTC()

	w, ok, err := s.LoadSessionWindow(ctx, "sA", now)
	if err != nil || !ok {
		t.Fatalf("LoadSessionWindow(sA) = ok=%v err=%v, want ok", ok, err)
	}
	if w.ProjectID != projectID {
		t.Errorf("ProjectID = %d, want %d", w.ProjectID, projectID)
	}
	if !w.StartedAt.Equal(base) {
		t.Errorf("StartedAt = %v, want %v", w.StartedAt, base)
	}
	if w.EndedAt.After(now) || w.EndedAt.Before(w.StartedAt) {
		t.Errorf("EndedAt = %v, want within [StartedAt, now]", w.EndedAt)
	}

	if _, ok, err := s.LoadSessionWindow(ctx, "no-such-session", now); err != nil || ok {
		t.Errorf("LoadSessionWindow(unknown) = ok=%v err=%v, want false/nil", ok, err)
	}
	if _, exists, err := s.LookupSessionWindow(ctx, "no-such-session", now); err != nil || exists {
		t.Errorf("LookupSessionWindow(unknown) = exists=%v err=%v, want false/nil", exists, err)
	}
	if lw, exists, err := s.LookupSessionWindow(ctx, "sA", now); err != nil || !exists || lw.ProjectID != projectID {
		t.Errorf("LookupSessionWindow(sA) = %+v exists=%v err=%v", lw, exists, err)
	}

	link := 14 * 24 * time.Hour
	since, until := SessionOwnershipSpan(SessionWindow{StartedAt: base, EndedAt: base.Add(time.Hour)}, link, base.Add(30*24*time.Hour))
	if !since.Equal(base.Add(-link)) || !until.Equal(base.Add(time.Hour+link)) {
		t.Errorf("span = [%v, %v), want [start-link, end+link)", since, until)
	}
	// An until past now is clamped just after now.
	_, until = SessionOwnershipSpan(SessionWindow{StartedAt: base, EndedAt: base}, link, base.Add(time.Hour))
	if !until.Equal(base.Add(time.Hour + time.Minute)) {
		t.Errorf("clamped until = %v, want now+1m", until)
	}
	// A zero link window falls back to the default.
	since, _ = SessionOwnershipSpan(SessionWindow{StartedAt: base, EndedAt: base}, 0, base)
	if !since.Equal(base.Add(-projectroi.DefaultLinkWindow)) {
		t.Errorf("since with zero link window = %v, want start-DefaultLinkWindow", since)
	}
}

// TestLoadProjectLOCExcludesDocsLines pins the 2026-09-28 honesty fix: a
// docs file's lines are never counted as AI "code" lines on the Projects
// surfaces (list + detail), and the comment total rides beside the code
// total.
func TestLoadProjectLOCExcludesDocsLines(t *testing.T) {
	t.Parallel()
	s, db := newTestStore(t)
	ctx := context.Background()
	root := "/repo/docsexcl"
	base := time.Now().UTC().Add(-time.Hour)

	events := []models.ToolEvent{
		editEvent("s1", root, root+"/a.go", "e1", "a := 1", `// explain a\na := 2`, base),
		editEvent("s1", root, root+"/GUIDE.md", "e2", "old", `line one\nline two\nline three\nline four`, base.Add(time.Minute)),
	}
	if _, err := s.Ingest(ctx, events, nil, IngestOptions{}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	projectID, err := s.ProjectIDForRoot(ctx, root)
	if err != nil {
		t.Fatalf("ProjectIDForRoot: %v", err)
	}

	// Ground truth straight from the rows: the docs row carries added_code
	// (the raw bucket) under a non-code category.
	var docsLines, codeLines, codeComment int
	if err := db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(CASE WHEN category <> 'code' THEN added_code + modified_code END), 0),
		       COALESCE(SUM(CASE WHEN category = 'code' THEN added_code + modified_code END), 0),
		       COALESCE(SUM(CASE WHEN category = 'code' THEN added_comment END), 0)
		  FROM file_changes WHERE project_id = ? AND actor = 'ai'`, projectID).Scan(&docsLines, &codeLines, &codeComment); err != nil {
		t.Fatalf("ground truth: %v", err)
	}
	if docsLines == 0 {
		t.Fatalf("fixture: the GUIDE.md edit produced no non-code lines; the test would prove nothing")
	}
	if codeComment == 0 {
		t.Fatalf("fixture: the a.go edit produced no comment line")
	}

	tot, err := s.LoadProjectLOCBreakdown(ctx, projectID, base.Add(-time.Hour), base.Add(time.Hour))
	if err != nil {
		t.Fatalf("LoadProjectLOCBreakdown: %v", err)
	}
	if got := tot.AIAdded + tot.AIModified; got != codeLines {
		t.Errorf("breakdown code lines = %d, want %d (code category only; docs rows carried %d)", got, codeLines, docsLines)
	}
	if tot.AIComment != codeComment {
		t.Errorf("breakdown comment lines = %d, want %d", tot.AIComment, codeComment)
	}
	added, modified, _, err := s.LoadProjectLOCTotals(ctx, projectID, base.Add(-time.Hour), base.Add(time.Hour))
	if err != nil || added != tot.AIAdded || modified != tot.AIModified {
		t.Errorf("LoadProjectLOCTotals = %d/%d err=%v, want the breakdown's %d/%d", added, modified, err, tot.AIAdded, tot.AIModified)
	}

	extras, err := s.LoadProjectListExtras(ctx, base.Add(-time.Hour), base.Add(time.Hour))
	if err != nil {
		t.Fatalf("LoadProjectListExtras: %v", err)
	}
	e := extras[projectID]
	if e == nil || e.AILines30d != codeLines || e.AIComment30d != codeComment {
		t.Errorf("list extra = %+v, want AILines30d=%d AIComment30d=%d", e, codeLines, codeComment)
	}
}
