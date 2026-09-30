package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guidance"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestAPIProjectSkillsEmptyCorpus pins the empty shape: a project with no
// skills, no snapshots and no git step renders every list as [] (never
// null), git state "not_scanned" and no observed_since.
func TestAPIProjectSkillsEmptyCorpus(t *testing.T) {
	s, root := newTestServer(t)
	st := store.New(s.opts.DB)
	projectID, err := st.ProjectIDForRoot(context.Background(), root)
	if err != nil || projectID == 0 {
		t.Fatalf("ProjectIDForRoot: %d %v", projectID, err)
	}
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/project/"+itoa64(projectID)+"/skills", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, k := range []string{
		`"skills":[]`, `"spans":[]`, `"cells":[]`, `"unmatched_invocations":[]`,
		`"ambiguous_invocations":[]`, `"state":"not_scanned"`, `"observed_since":""`,
	} {
		if !strings.Contains(body, k) {
			t.Errorf("empty-corpus body missing %s: %s", k, body)
		}
	}
	if strings.Contains(body, "null") {
		t.Errorf("empty-corpus body carries a null: %s", body)
	}
}

func TestAPIProjectSkillsUnknownProject(t *testing.T) {
	s, _ := newTestServer(t)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/project/999999/skills", nil))
	if rr.Code != http.StatusNotFound {
		t.Errorf("unknown project status = %d, want 404", rr.Code)
	}
}

// TestComposeProjectSkillsPopulated runs the shared composition over a
// seeded project: one committed skill, a session whose hook snapshot saw it,
// the reflog placing HEAD on the introducing commit, and one Skill-tool
// invocation joined by tool_use_id.
func TestComposeProjectSkillsPopulated(t *testing.T) {
	s, root, projectID, _, _ := seedProjectsFixture(t)
	ctx := context.Background()
	st := store.New(s.opts.DB)
	const (
		md   = ".claude/skills/deploy/SKILL.md"
		blob = "aaaaaaaa11111111111111111111111111111111"
		sha  = "sha1" // the fixture's commit
	)
	start := time.Now().UTC().Add(-2 * time.Hour)
	if _, err := st.UpsertGuidanceScan(ctx, root, []guidance.File{{
		Tool: "claude-code", Kind: guidance.KindSkill, Scope: guidance.ScopeProject,
		RelPath: md, AbsPath: root + "/" + md, Name: "deploy", ContentHash: "c",
	}}, start); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveSkillTree(ctx, projectID, sha, "ok", []store.SkillTreeFileRow{{RelPath: md, Mode: "100644", BlobOID: blob}}, start); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.InsertHeadMoves(ctx, projectID, []store.HeadMoveRow{{MovedAt: start.Add(-24 * time.Hour), SHA: sha, Kind: "commit"}}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSkillScanState(ctx, store.SkillScanState{ProjectID: projectID, LastScanAt: start, HeadSHA: sha, ReflogSince: start.Add(-24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	mem := []store.SkillSnapshotMember{{Scope: "project", RelPath: md, DirKey: ".claude/skills/deploy", Name: "deploy", State: "present", BlobOID: blob}}
	if err := st.InsertSkillSnapshot(ctx, store.SkillSnapshot{
		SessionID: "sess1", Tool: "claude-code", Event: "session_start",
		Source: "startup", ObservedAt: start, Complete: true, HomeResolved: true, Members: mem,
	}); err != nil {
		t.Fatal(err)
	}

	got, err := ComposeProjectSkills(ctx, st, ProjectSkillsInput{
		ProjectID: projectID, Days: 30, Since: time.Now().UTC().Add(-30 * 24 * time.Hour), Until: time.Now().UTC().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("ComposeProjectSkills: %v", err)
	}
	if len(got.Skills) != 1 || got.Skills[0].Current.InGit != "committed" || got.Skills[0].Current.HeadVersion != "aaaaaaaa" {
		t.Fatalf("skills = %+v", got.Skills)
	}
	if got.Capture.Git.State != "ok" || got.Capture.ObservedSince == "" || !got.Capture.SnapshotCapable["claude-code"] {
		t.Errorf("capture = %+v", got.Capture)
	}
	if len(got.Spans) != 1 || got.Spans[0].Observed.State != "observed" || got.Spans[0].Head.State != "committed" {
		t.Errorf("spans = %+v, want one observed + committed span", got.Spans)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "null") && !strings.Contains(string(raw), `"moved_from":null`) {
		t.Errorf("populated body carries an unexpected null: %s", raw)
	}
}
