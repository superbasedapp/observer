package dashboard

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/commitlog"
	"github.com/marmutapp/superbased-observer/internal/loc"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/projectroi"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// seedCoOwnedFixture builds one project where two sessions co-contribute
// to one commit and a third session reaches nothing:
//
//   - sBig: a 3-line code edit to big.go (plus a comment line);
//   - sSmall: a 1-line code edit to small.go;
//   - sIdle: a prompt and an edit to idle.go that no commit carries;
//   - cBoth at base+30m carries big.go + small.go -> owned by sBig
//     (most_code_lines), sSmall a contributor.
func seedCoOwnedFixture(t *testing.T) (s *Server, projectID int64) {
	t.Helper()
	s, _ = newTestServer(t)
	root := t.TempDir()
	ctx := context.Background()
	st := store.New(s.opts.DB)
	base := time.Now().UTC().Add(-3 * time.Hour)

	ev := func(sess, actionType, target, raw, eventID string, ts time.Time) models.ToolEvent {
		return models.ToolEvent{
			SessionID: sess, ProjectRoot: root, Target: target, ActionType: actionType,
			RawToolInput: raw, RawToolName: "Edit", Tool: models.ToolClaudeCode,
			SourceFile: "/tmp/co.jsonl", SourceEventID: eventID, Timestamp: ts, Success: true,
		}
	}
	edit := func(sess, file, oldS, newS, eventID string, ts time.Time) models.ToolEvent {
		return ev(sess, models.ActionEditFile, root+"/"+file,
			`{"file_path":"`+root+`/`+file+`","old_string":"`+oldS+`","new_string":"`+newS+`"}`, eventID, ts)
	}
	events := []models.ToolEvent{
		ev("sBig", models.ActionUserPrompt, "build the big thing", "build the big thing", "pBig", base),
		edit("sBig", "big.go", "x := 1", `// why x\nx := 2\ny := 3\nz := 4`, "eBig", base.Add(time.Minute)),
		ev("sSmall", models.ActionUserPrompt, "small tweak", "small tweak", "pSmall", base.Add(5*time.Minute)),
		edit("sSmall", "small.go", "s := 1", "s := 2", "eSmall", base.Add(6*time.Minute)),
		ev("sIdle", models.ActionUserPrompt, "explore only", "explore only", "pIdle", base.Add(7*time.Minute)),
		edit("sIdle", "idle.go", "i := 1", "i := 2", "eIdle", base.Add(8*time.Minute)),
	}
	if _, err := st.Ingest(ctx, events, nil, store.IngestOptions{}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	var err error
	projectID, err = st.ProjectIDForRoot(ctx, root)
	if err != nil {
		t.Fatalf("ProjectIDForRoot: %v", err)
	}
	commits := []commitlog.Commit{{
		SHA: "cboth", AuthorHash: "au", AuthoredAt: base.Add(30 * time.Minute), CommittedAt: base.Add(30 * time.Minute),
		Subject: "feat: both",
		Files: []commitlog.CommitFile{
			{RelPath: "big.go", PathHash: loc.PathHash(root, root+"/big.go"), Added: 4},
			{RelPath: "small.go", PathHash: loc.PathHash(root, root+"/small.go"), Added: 1},
		},
	}}
	if _, err := st.UpsertCommits(ctx, projectID, commits, base.Add(35*time.Minute)); err != nil {
		t.Fatalf("UpsertCommits: %v", err)
	}
	if err := st.SetCommitScanState(ctx, store.ScanState{
		ProjectID: projectID, LastSHA: "cboth", LastCommittedAt: base.Add(30 * time.Minute), LastScanAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("SetCommitScanState: %v", err)
	}
	return s, projectID
}

func getSessionCommits(t *testing.T, s *Server, sessionID string) (int, apiSessionCommitsResponse) {
	t.Helper()
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/session/"+sessionID+"/commits", nil))
	var got apiSessionCommitsResponse
	if rr.Code == http.StatusOK {
		if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v; body=%s", err, rr.Body.String())
		}
	}
	return rr.Code, got
}

// TestAPISessionCommits pins GET /api/session/{id}/commits: the owner sees
// owner=true, a co-contributor sees owner=false naming the other session
// as owner, shares sum to 1, a session whose work reached no commit gets an
// honest empty list (rows [], never null), and an unknown session is 404.
func TestAPISessionCommits(t *testing.T) {
	s, projectID := seedCoOwnedFixture(t)

	code, big := getSessionCommits(t, s, "sBig")
	if code != http.StatusOK {
		t.Fatalf("sBig status %d", code)
	}
	if big.SessionID != "sBig" || big.ProjectID != projectID || big.LinkWindowDays != 14 || big.CommitCapture != "ok" {
		t.Errorf("sBig envelope = %+v", big)
	}
	if len(big.Rows) != 1 {
		t.Fatalf("sBig rows = %+v, want 1", big.Rows)
	}
	b := big.Rows[0]
	if b.SHA != "cboth" || b.Subject != "feat: both" || !b.Owner || b.OwnerSessionID != "sBig" {
		t.Errorf("sBig row = %+v, want cboth owned by sBig", b)
	}
	if b.Reason != projectroi.OwnerMostCodeLines || b.ShareBasis != projectroi.ShareBasisCodeLines {
		t.Errorf("sBig reason/basis = %q/%q", b.Reason, b.ShareBasis)
	}
	if b.CodeLines == 0 || b.CommentLines == 0 || b.Files != 1 || b.Prompts != 1 {
		t.Errorf("sBig contribution = %+v, want code>0 comment>0 files=1 prompts=1", b)
	}
	if b.Split.CodeLines != int64(b.CodeLines) || b.Split.CommentLines != int64(b.CommentLines) || b.Split.CommentShare == nil {
		t.Errorf("sBig split = %+v, want SplitAuthored(code, comment)", b.Split)
	}

	code, small := getSessionCommits(t, s, "sSmall")
	if code != http.StatusOK || len(small.Rows) != 1 {
		t.Fatalf("sSmall status %d rows %+v, want 200 + 1 row", code, small.Rows)
	}
	sm := small.Rows[0]
	if sm.Owner || sm.OwnerSessionID != "sBig" || sm.Reason != projectroi.OwnerMostCodeLines {
		t.Errorf("sSmall row = %+v, want contributed, owned by sBig", sm)
	}
	if math.Abs(sm.Share+b.Share-1) > 1e-9 || sm.Share >= b.Share {
		t.Errorf("shares sBig=%v sSmall=%v, want summing to 1 with sBig larger", b.Share, sm.Share)
	}

	code, idle := getSessionCommits(t, s, "sIdle")
	if code != http.StatusOK {
		t.Fatalf("sIdle status %d", code)
	}
	if idle.Rows == nil || len(idle.Rows) != 0 || idle.Truncated {
		t.Errorf("sIdle = %+v, want rows [] untruncated", idle)
	}

	if code, _ := getSessionCommits(t, s, "no-such-session"); code != http.StatusNotFound {
		t.Errorf("unknown session status = %d, want 404", code)
	}

	// Raw wire: rows serialize as [], never null, for the empty case.
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/session/sIdle/commits", nil))
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if string(raw["rows"]) != "[]" {
		t.Errorf("empty rows on the wire = %s, want []", raw["rows"])
	}
}

// TestAPISessionCommitsTruncation pins that a capped loader is reported
// on the session endpoint, never a silently partial list.
func TestAPISessionCommitsTruncation(t *testing.T) {
	s, _ := seedCoOwnedFixture(t)
	withCap(t, &promptLinkCap, 1)
	code, got := getSessionCommits(t, s, "sBig")
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	if !got.Truncated || len(got.TruncatedInputs) != 1 || got.TruncatedInputs[0] != "prompts" {
		t.Errorf("truncation meta = %+v, want truncated on prompts", got.apiTruncationMeta)
	}
}

// TestAPIProjectCommitsOwner pins the ledger's owner object: a
// co-contributed commit names its owner, the ranking reason verbatim, and
// every contributor with its share and code/comment split, over the SAME
// link set as the row's ai_files/ai_lines.
func TestAPIProjectCommitsOwner(t *testing.T) {
	s, projectID := seedCoOwnedFixture(t)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/project/"+itoa64(projectID)+"/commits", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body=%s", rr.Code, rr.Body.String())
	}
	var got apiProjectCommitsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Rows) != 1 {
		t.Fatalf("rows = %+v, want 1", got.Rows)
	}
	c := got.Rows[0]
	o := c.Owner
	if o.SessionID != "sBig" || o.Reason != projectroi.OwnerMostCodeLines || o.ShareBasis != projectroi.ShareBasisCodeLines {
		t.Errorf("owner = %+v, want sBig / most_code_lines / code_lines", o)
	}
	if len(o.Contributors) != 2 || o.Contributors[0].SessionID != "sBig" || o.Contributors[1].SessionID != "sSmall" {
		t.Fatalf("contributors = %+v, want [sBig, sSmall] ranked", o.Contributors)
	}
	var codeSum, commentSum int
	for _, k := range o.Contributors {
		codeSum += k.CodeLines
		commentSum += k.CommentLines
		if k.FirstPromptAt == "" || k.Prompts != 1 || k.Files != 1 {
			t.Errorf("contributor %+v, want first_prompt_at set, prompts=1, files=1", k)
		}
	}
	if codeSum != c.AILines || commentSum != c.AICommentLines {
		t.Errorf("contributors carry %d code / %d comment, row carries %d / %d - must be the same link set", codeSum, commentSum, c.AILines, c.AICommentLines)
	}
	if c.AISplit.CodeLines != int64(c.AILines) || c.AISplit.CommentLines != int64(c.AICommentLines) {
		t.Errorf("ai_split = %+v, want SplitAuthored(ai_lines, ai_comment_lines)", c.AISplit)
	}
}

// TestAPIProjectCommitsOwnerSoleAndNone pins the sole-contributor reason on
// the shared fixture and the none reason (with no guessed session) on a
// commit no AI edit reached.
func TestAPIProjectCommitsOwnerSoleAndNone(t *testing.T) {
	s, root, projectID, _, _ := seedProjectsFixture(t)
	st := store.New(s.opts.DB)
	ctx := context.Background()
	at := time.Now().UTC().Add(-20 * time.Minute)
	if _, err := st.UpsertCommits(ctx, projectID, []commitlog.Commit{{
		SHA: "human1", AuthorHash: "au", AuthoredAt: at, CommittedAt: at, Subject: "chore: by hand",
		Files: []commitlog.CommitFile{{RelPath: "z.go", PathHash: loc.PathHash(root, root+"/z.go"), Added: 1}},
	}}, at); err != nil {
		t.Fatalf("UpsertCommits: %v", err)
	}
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/project/"+itoa64(projectID)+"/commits", nil))
	var got apiProjectCommitsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	bySHA := map[string]apiProjectCommitRow{}
	for _, r := range got.Rows {
		bySHA[r.SHA] = r
	}
	if o := bySHA["sha1"].Owner; o.SessionID != "sess1" || o.Reason != projectroi.OwnerSoleContributor || len(o.Contributors) != 1 || o.Contributors[0].Share != 1 {
		t.Errorf("sha1 owner = %+v, want sess1 sole_contributor share 1", o)
	}
	if o := bySHA["human1"].Owner; o.SessionID != "" || o.Reason != projectroi.OwnerNoneNoAIEdits || o.Contributors == nil || len(o.Contributors) != 0 {
		t.Errorf("human1 owner = %+v, want no owner, no_ai_edits, contributors []", o)
	}
}

// TestAPISessionCommitsHonoursHiddenProjectsSection pins that the session
// endpoint, which discloses commit subjects (Projects-section data), is
// refused when an org hides the Projects section - the same refusal the
// governance guard gives /api/project/{id}/commits - while the parent
// session detail itself stays readable.
func TestAPISessionCommitsHonoursHiddenProjectsSection(t *testing.T) {
	s, _ := seedCoOwnedFixture(t)
	s.opts.Governance = governedProvider(t, []string{string(SectionProjects)}, nil, nil, nil)
	code, _ := getSessionCommits(t, s, "sBig")
	if code != http.StatusNotFound {
		t.Errorf("hidden Projects section: status %d, want 404", code)
	}
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/session/sBig/loc", nil))
	if rr.Code != http.StatusOK {
		t.Errorf("sibling /loc under a hidden Projects section: status %d, want 200", rr.Code)
	}
}
