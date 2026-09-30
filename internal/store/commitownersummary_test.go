package store

import (
	"context"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/commitlog"
	"github.com/marmutapp/superbased-observer/internal/loc"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/projectroi"
)

// The sentinels below are planted in the node-local commit columns that must
// NEVER reach the org wire (COMMIT-2/COMMIT-3): the author hash and the
// per-file path. The subject sentinel may ship, but only under the raw-content
// posture.
const (
	coWireAuthorSentinel  = "SBCOAUTHORSENT"
	coWireRelPathSentinel = "SBCORELPATHSENT"
	coWireSubjectSentinel = "SBCOSUBJECTSENT"
)

// commitOwnershipWireFixture seeds one project, relative to now:
//
//   - wA (prompt, a 3-line code edit to a.go and a docs edit) and wB (prompt,
//     a 1-line edit to b.go) co-contribute to "own1", committed 2h ago: owned
//     by wA on most_code_lines;
//   - "human1" (2h ago) touches only notes.txt: no AI edit reached it, so it
//     must never ship;
//   - "gone1" (90m ago) carried wA's c.go edit but fell out of HEAD: it ships
//     as an identity-only unreachable row;
//   - "merge1" (80m ago) is a merge: never ships;
//   - "old1" (10 days ago) is owned by wOld but outside the 7-day window.
func commitOwnershipWireFixture(t *testing.T) (*Store, string) {
	t.Helper()
	s, _ := newTestStore(t)
	ctx := context.Background()
	root := "/repo/cowire"
	now := time.Now().UTC().Truncate(time.Second)
	base := now.Add(-3 * time.Hour)
	old := now.Add(-10 * 24 * time.Hour)

	events := []models.ToolEvent{
		promptEvent("wOld", root, "old work", "pOld", old),
		editEvent("wOld", root, root+"/old.go", "eOld", "o := 1", "o := 2", old.Add(time.Minute)),
		promptEvent("wA", root, "add the parser", "pA", base),
		editEvent("wA", root, root+"/a.go", "eA1", "a := 1", `a := 2\nb := 3\nc := 4`, base.Add(time.Minute)),
		editEvent("wA", root, root+"/README.md", "eA2", "old words", `new words\nmore words`, base.Add(2*time.Minute)),
		editEvent("wA", root, root+"/c.go", "eA3", "c := 1", "c := 2", base.Add(3*time.Minute)),
		promptEvent("wB", root, "tweak b", "pB", base.Add(10*time.Minute)),
		editEvent("wB", root, root+"/b.go", "eB1", "b := 1", "b := 2", base.Add(11*time.Minute)),
	}
	if _, err := s.Ingest(ctx, events, nil, IngestOptions{}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	projectID, err := s.ProjectIDForRoot(ctx, root)
	if err != nil {
		t.Fatalf("ProjectIDForRoot: %v", err)
	}
	ph := func(p string) string { return loc.PathHash(root, root+"/"+p) }
	file := func(p string, added int) commitlog.CommitFile {
		return commitlog.CommitFile{RelPath: coWireRelPathSentinel + "/" + p, PathHash: ph(p), Added: added}
	}
	commit := func(sha string, at time.Time, merge bool, files ...commitlog.CommitFile) commitlog.Commit {
		c := commitlog.Commit{
			SHA: sha, AuthorHash: coWireAuthorSentinel, AuthoredAt: at, CommittedAt: at,
			Subject: coWireSubjectSentinel + " " + sha, IsMerge: merge, Files: files,
		}
		if merge {
			c.Parents = []string{"p1", "p2"}
		}
		return c
	}
	commits := []commitlog.Commit{
		commit("old1", old.Add(5*time.Minute), false, file("old.go", 1)),
		commit("gone1", base.Add(5*time.Minute), false, file("c.go", 1)),
		commit("own1", base.Add(60*time.Minute), false, file("a.go", 3), file("b.go", 1), file("README.md", 2)),
		commit("human1", base.Add(60*time.Minute), false, file("notes.txt", 1)),
		commit("merge1", base.Add(70*time.Minute), true, file("a.go", 3)),
	}
	if _, err := s.UpsertCommits(ctx, projectID, commits, now); err != nil {
		t.Fatalf("UpsertCommits: %v", err)
	}
	reachable := map[string]bool{"old1": true, "own1": true, "human1": true, "merge1": true}
	if err := s.MarkCommitsReachability(ctx, projectID, reachable, time.Time{}); err != nil {
		t.Fatalf("MarkCommitsReachability: %v", err)
	}
	return s, root
}

// coWireFixtureSHAs are the fixture's raw commit ids; the wire keys rows by
// the sha256 hash (review 2026-09-29 finding 3), so a test reverses it here.
var coWireFixtureSHAs = []string{"old1", "gone1", "own1", "human1", "merge1"}

// coWireBySHA indexes wire rows by the fixture's RAW sha, resolved from each
// row's CommitSHAHash (the raw CommitSHA is empty on the default posture).
func coWireBySHA(rows []orgcontract.CommitOwnershipRow) map[string]orgcontract.CommitOwnershipRow {
	out := map[string]orgcontract.CommitOwnershipRow{}
	for _, r := range rows {
		for _, sha := range coWireFixtureSHAs {
			if sha256Hex(sha) == r.CommitSHAHash {
				out[sha] = r
			}
		}
	}
	return out
}

// TestSelectCommitOwnershipRows pins the emission rule and the row content:
// owned commits ship with owner, reason, ranked contributors and their
// shares; an unreachable commit ships identity-only; a human commit, a merge
// and a commit outside the window never ship.
func TestSelectCommitOwnershipRows(t *testing.T) {
	t.Parallel()
	s, root := commitOwnershipWireFixture(t)
	ctx := context.Background()

	rows, err := s.SelectCommitOwnershipRows(ctx, ScopeOptions{}, false, 0)
	if err != nil {
		t.Fatalf("SelectCommitOwnershipRows: %v", err)
	}
	by := coWireBySHA(rows)
	_, hasOwn := by["own1"]
	_, hasGone := by["gone1"]
	if len(rows) != 2 || !hasOwn || !hasGone {
		t.Fatalf("rows = %+v, want exactly own1 + gone1", rows)
	}
	for _, r := range rows {
		if r.CommitSHA != "" {
			t.Errorf("metadata posture shipped the RAW commit id %q (finding 3)", r.CommitSHA)
		}
	}
	var wantHash string
	if err := s.db.QueryRowContext(ctx, `SELECT root_path_hash FROM projects WHERE root_path = ?`, root).Scan(&wantHash); err != nil {
		t.Fatalf("root hash: %v", err)
	}

	own := by["own1"]
	if own.ProjectRootHash != wantHash || wantHash == "" {
		t.Errorf("own1 project_root_hash = %q, want %q", own.ProjectRootHash, wantHash)
	}
	if own.OwnerSessionID != "wA" || own.OwnerReason != projectroi.OwnerMostCodeLines {
		t.Errorf("own1 owner = %q/%q, want wA/%s", own.OwnerSessionID, own.OwnerReason, projectroi.OwnerMostCodeLines)
	}
	if !own.Reachable || own.IsMerge || own.ShareBasis != projectroi.ShareBasisCodeLines {
		t.Errorf("own1 flags = %+v", own)
	}
	if own.FilesCount != 3 || own.Added != 6 || own.AIFiles != 3 {
		t.Errorf("own1 counts files=%d added=%d ai_files=%d, want 3/6/3", own.FilesCount, own.Added, own.AIFiles)
	}
	if len(own.Contributors) != 2 || own.Contributors[0].SessionID != "wA" || own.Contributors[1].SessionID != "wB" {
		t.Fatalf("own1 contributors = %+v, want [wA wB]", own.Contributors)
	}
	var share float64
	var code, comment int64
	for _, c := range own.Contributors {
		share += c.Share
		code += c.CodeLines
		comment += c.CommentLines
	}
	if math.Abs(share-1) > 1e-9 {
		t.Errorf("own1 shares sum to %v, want 1", share)
	}
	if own.AICodeLines != code || own.AICommentLines != comment || code == 0 {
		t.Errorf("own1 ai lines %d/%d, want the contributor sums %d/%d (non-zero code)", own.AICodeLines, own.AICommentLines, code, comment)
	}
	if own.RuleVersion != projectroi.OwnershipRuleVersion {
		t.Errorf("rule_version = %d, want %d", own.RuleVersion, projectroi.OwnershipRuleVersion)
	}
	if own.Subject != "" {
		t.Errorf("own1 subject = %q under the metadata posture, want empty (not shared)", own.Subject)
	}
	if _, err := time.Parse(time.RFC3339, own.CommittedAt); err != nil {
		t.Errorf("committed_at %q is not RFC3339: %v", own.CommittedAt, err)
	}

	gone := by["gone1"]
	if gone.Reachable || gone.OwnerSessionID != "" || gone.OwnerReason != projectroi.OwnerNoneUnreachable {
		t.Errorf("gone1 = %+v, want unreachable, no owner, reason %s", gone, projectroi.OwnerNoneUnreachable)
	}
	if gone.FilesCount != 0 || gone.Added != 0 || len(gone.Contributors) != 0 || gone.Subject != "" {
		t.Errorf("gone1 carries more than its identity: %+v", gone)
	}

	// Newest committed first (truncation drops the oldest).
	if rows[0].CommitSHAHash != sha256Hex("own1") {
		t.Errorf("row order = %s, %s; want own1 (newest) first", rows[0].CommitSHAHash, rows[1].CommitSHAHash)
	}
}

// TestSelectCommitOwnershipRowsSubjectGateAndNoAuthor pins the posture: the
// subject ships only when shipSubject is set, and no author hash or path
// ever reaches the wire, under either posture.
func TestSelectCommitOwnershipRowsSubjectGateAndNoAuthor(t *testing.T) {
	t.Parallel()
	s, _ := commitOwnershipWireFixture(t)
	ctx := context.Background()
	for _, ship := range []bool{false, true} {
		rows, err := s.SelectCommitOwnershipRows(ctx, ScopeOptions{}, ship, 0)
		if err != nil {
			t.Fatalf("SelectCommitOwnershipRows(ship=%v): %v", ship, err)
		}
		raw, err := json.Marshal(rows)
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{coWireAuthorSentinel, coWireRelPathSentinel, "author", "path_hash", "rel_path"} {
			if strings.Contains(string(raw), bad) {
				t.Errorf("ship=%v: wire carries %q: %s", ship, bad, raw)
			}
		}
		own := coWireBySHA(rows)["own1"]
		if ship && own.CommitSHA != "own1" {
			t.Errorf("ship=true: own1 raw sha = %q, want it shipped under the raw-content posture", own.CommitSHA)
		}
		if !ship && strings.Contains(string(raw), `"commit_sha":`) {
			t.Errorf("ship=false: a raw commit id reached the wire (finding 3): %s", raw)
		}
		if own.CommitSHAHash != sha256Hex("own1") {
			t.Errorf("ship=%v: own1 commit_sha_hash = %q, want sha256 of the sha", ship, own.CommitSHAHash)
		}
		if ship && own.Subject != coWireSubjectSentinel+" own1" {
			t.Errorf("ship=true: own1 subject = %q, want the stored (scrubbed) subject", own.Subject)
		}
		if !ship && strings.Contains(string(raw), coWireSubjectSentinel) {
			t.Errorf("ship=false: a subject leaked: %s", raw)
		}
		if gone := coWireBySHA(rows)["gone1"]; gone.Subject != "" {
			t.Errorf("ship=%v: the unreachable identity-only row carries a subject %q", ship, gone.Subject)
		}
	}
}

// TestSelectCommitOwnershipRowsHonoursScope pins the org-push project scope:
// a denylisted root ships nothing, and an allowlist naming no known root is a
// deliberate empty, never "ship everything".
func TestSelectCommitOwnershipRowsHonoursScope(t *testing.T) {
	t.Parallel()
	s, root := commitOwnershipWireFixture(t)
	ctx := context.Background()
	cases := []struct {
		name  string
		scope ScopeOptions
		want  int
	}{
		{"unscoped", ScopeOptions{}, 2},
		{"allowlisted", ScopeOptions{ProjectRootAllowlist: []string{root}}, 2},
		{"denylisted", ScopeOptions{ProjectRootDenylist: []string{root}}, 0},
		{"allowlist_of_unknown_root", ScopeOptions{ProjectRootAllowlist: []string{"/repo/elsewhere"}}, 0},
	}
	for _, c := range cases {
		rows, err := s.SelectCommitOwnershipRows(ctx, c.scope, false, 0)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if len(rows) != c.want {
			t.Errorf("%s: %d rows, want %d", c.name, len(rows), c.want)
		}
	}
}

// TestSelectUnpushedSinceCarriesCommitOwnership pins the orgpush wiring: the
// batch carries the family, stamped with the pusher, the subject gated on the
// share posture.
func TestSelectUnpushedSinceCarriesCommitOwnership(t *testing.T) {
	t.Parallel()
	s, _ := commitOwnershipWireFixture(t)
	ctx := context.Background()
	for _, tc := range []struct {
		name        string
		share       ShareOptions
		wantSubject bool
	}{
		{"metadata_only", ShareOptions{}, false},
		{"full_content", ShareOptions{FullContent: true}, true},
		{"admin_managed", ShareOptions{AdminManaged: true}, true},
	} {
		batch, err := s.SelectUnpushedSince(ctx, PushCursor{}, 1<<22, "org-1", "dev@acme.example", tc.share, ScopeOptions{})
		if err != nil {
			t.Fatalf("%s: SelectUnpushedSince: %v", tc.name, err)
		}
		if len(batch.CommitOwnership) != 2 {
			t.Fatalf("%s: CommitOwnership = %+v, want 2 rows", tc.name, batch.CommitOwnership)
		}
		if batch.Empty() {
			t.Errorf("%s: a batch carrying commit ownership reports Empty()", tc.name)
		}
		for _, r := range batch.CommitOwnership {
			if r.OrgID != "org-1" || r.UserEmail != "dev@acme.example" {
				t.Errorf("%s: row not stamped: %+v", tc.name, r)
			}
			if r.CommitSHAHash == sha256Hex("own1") && (r.Subject != "") != tc.wantSubject {
				t.Errorf("%s: own1 subject = %q, want shipped=%v", tc.name, r.Subject, tc.wantSubject)
			}
			if (r.CommitSHA != "") != tc.wantSubject {
				t.Errorf("%s: raw commit id shipped=%v, want %v (finding 3)", tc.name, r.CommitSHA != "", tc.wantSubject)
			}
		}
	}
}

// TestCommitOwnershipUnreachableFlipShipsPastTheEmitWindow is review
// 2026-09-29 finding 5: a commit the org stored while it was in the 7-day
// window that later falls out of HEAD must still ship its identity-only
// unreachable flip, even though it is now older than the emit window. Owned
// rows stay emit-window-only.
func TestCommitOwnershipUnreachableFlipShipsPastTheEmitWindow(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	emitSince := now.AddDate(0, 0, -commitOwnershipOrgWindowDays)
	res := CommitOwnershipResult{
		Commits: []ProjectCommitRow{
			{ID: 1, SHA: "deadbeef", CommittedAt: now.AddDate(0, 0, -9), Reachable: false},
			{ID: 2, SHA: "oldowned", CommittedAt: now.AddDate(0, 0, -9), Reachable: true},
			{ID: 3, SHA: "oldmerge", CommittedAt: now.AddDate(0, 0, -9), Reachable: false, IsMerge: true},
		},
		Ownership: map[int64]projectroi.CommitOwnership{
			1: {CommitID: 1, Reason: projectroi.OwnerNoneUnreachable},
			2: {CommitID: 2, OwnerSessionID: "s", Reason: projectroi.OwnerSoleContributor},
			3: {CommitID: 3, Reason: projectroi.OwnerNoneMerge},
		},
	}
	rows := commitOwnershipWireRows(res, "roothash", emitSince, false)
	if len(rows) != 1 {
		t.Fatalf("rows = %+v, want exactly the 9-day-old unreachable flip", rows)
	}
	r := rows[0]
	if r.CommitSHAHash != sha256Hex("deadbeef") || r.Reachable || r.OwnerSessionID != "" || r.CommitSHA != "" {
		t.Fatalf("flip row = %+v, want identity-only, hash-keyed, no raw sha", r)
	}
}

// TestSelectCommitOwnershipRowsShipsOldUnreachableFlip drives finding 5
// through the store: the fixture's 10-day-old owned commit "old1" falls out
// of HEAD, and its identity-only flip now ships (it never did before).
func TestSelectCommitOwnershipRowsShipsOldUnreachableFlip(t *testing.T) {
	t.Parallel()
	s, root := commitOwnershipWireFixture(t)
	ctx := context.Background()
	projectID, err := s.ProjectIDForRoot(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	// old1 rebased away; everything else stays as the fixture set it.
	reachable := map[string]bool{"own1": true, "human1": true, "merge1": true}
	if err := s.MarkCommitsReachability(ctx, projectID, reachable, time.Time{}); err != nil {
		t.Fatalf("MarkCommitsReachability: %v", err)
	}
	rows, err := s.SelectCommitOwnershipRows(ctx, ScopeOptions{}, false, 0)
	if err != nil {
		t.Fatalf("SelectCommitOwnershipRows: %v", err)
	}
	old, ok := coWireBySHA(rows)["old1"]
	if !ok {
		t.Fatalf("the 10-day-old commit's unreachable flip never shipped: %+v", rows)
	}
	if old.Reachable || old.OwnerSessionID != "" || len(old.Contributors) != 0 || old.Subject != "" || old.FilesCount != 0 {
		t.Fatalf("old1 flip carries more than its identity: %+v", old)
	}
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want own1 + gone1 + the old1 flip", len(rows))
	}
}
