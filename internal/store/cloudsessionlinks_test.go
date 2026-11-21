package store

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/commitlog"
	"github.com/marmutapp/superbased-observer/internal/delivery"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/projectroi"
)

// cloudCreditFixture is one local project on github.com/acme/app with a
// Copilot cloud session that claimed PR #7, the PR stored from the code host
// (its branch commit bot1 and its squash landing land7), a local-only squash
// subj9 naming PR #9 that a Devin session claimed (no PR row), and a human
// commit.
type cloudCreditFixture struct {
	s         *Store
	projectID int64
	ids       map[string]int64
	start     time.Time
}

func newCloudCreditFixture(t *testing.T) cloudCreditFixture {
	t.Helper()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	start := now.Add(-5 * time.Hour)
	pid, err := s.UpsertProject(ctx, "/repo/cloudcredit", "git@github.com:acme/app.git")
	if err != nil {
		t.Fatal(err)
	}
	// The cloud sessions live under the synthetic project (CA-D3); credit
	// matches by repository, not by project id.
	cloudPID, err := s.ResolveRemoteProject(ctx, "github.com/acme/other")
	if err != nil {
		t.Fatal(err)
	}
	for _, sess := range []models.Session{
		{ID: "copilot-1", ProjectID: cloudPID, Tool: models.ToolCopilot, StartedAt: start},
		{ID: "devin-1", ProjectID: cloudPID, Tool: "devin", StartedAt: start.Add(time.Minute)},
	} {
		if err := s.UpsertSession(ctx, sess); err != nil {
			t.Fatal(err)
		}
	}
	commit := func(sha, subject string, at time.Time, merge bool) commitlog.Commit {
		c := commitlog.Commit{
			SHA: sha, AuthorHash: "bot", AuthoredAt: at, CommittedAt: at, Subject: subject, IsMerge: merge,
			Files: []commitlog.CommitFile{{RelPath: "a.go", PathHash: "h-" + sha, Added: 2}, {RelPath: "b.go", PathHash: "h2-" + sha, Added: 1}},
		}
		if merge {
			c.Parents = []string{"p1", "p2"}
		}
		return c
	}
	commits := []commitlog.Commit{
		commit("bot1", "Fix the parser", start.Add(time.Hour), false),
		commit("land7", "Fix the parser (#7)", start.Add(2*time.Hour), false),
		commit("subj9", "Add retries (#9)", start.Add(3*time.Hour), false),
		commit("human1", "Tidy up", start.Add(3*time.Hour), false),
		commit("merge1", "Merge pull request #7 from acme/copilot/fix", start.Add(2*time.Hour), true),
	}
	if _, err := s.UpsertCommits(ctx, pid, commits, now); err != nil {
		t.Fatal(err)
	}
	reach := map[string]bool{"bot1": true, "land7": true, "subj9": true, "human1": true, "merge1": true}
	if err := s.MarkCommitsReachability(ctx, pid, reach, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpsertPullRequest(ctx, delivery.PullRequest{
		LinkID: 1, Provider: delivery.ProviderGitHub, Host: "github.com", RepoSlug: "acme/app", Number: 7,
		State: delivery.PRMerged, MergeCommitSHA: "land7", HeadRef: "copilot/fix", CreatedAt: start.Add(30 * time.Minute),
	}, []delivery.PRCommit{{SHA: "bot1"}}); err != nil {
		t.Fatal(err)
	}
	n, err := s.RecordCloudSessionLinks(ctx, []CloudSessionLink{
		{SessionID: "copilot-1", Connector: "copilot-agent", Remote: "github.com/ACME/app", PRNumber: 7},
		{SessionID: "devin-1", Connector: "devin", Remote: "https://github.com/acme/app", PRNumber: 9},
	}, now)
	if err != nil || n != 2 {
		t.Fatalf("RecordCloudSessionLinks = %d, %v", n, err)
	}
	f := cloudCreditFixture{s: s, projectID: pid, ids: map[string]int64{}, start: start}
	for _, sha := range []string{"bot1", "land7", "subj9", "human1", "merge1"} {
		var id int64
		if err := s.db.QueryRowContext(ctx, `SELECT id FROM project_commits WHERE sha = ?`, sha).Scan(&id); err != nil {
			t.Fatal(err)
		}
		f.ids[sha] = id
	}
	return f
}

// TestLoadCommitOwnershipCreditsCloudSessions runs the credit table end to
// end over the store: C1 (the PR lists the sha), C2 (the PR's landing
// commit), C3 (a local squash subject), and the commits it must leave
// alone (a merge, a human commit).
func TestLoadCommitOwnershipCreditsCloudSessions(t *testing.T) {
	t.Parallel()
	f := newCloudCreditFixture(t)
	ctx := context.Background()
	res, err := f.s.LoadCommitOwnership(ctx, f.projectID, f.start.Add(-time.Hour), time.Now().Add(time.Hour), 0, OwnershipCaps{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][2]string{
		"bot1":   {"copilot-1", projectroi.OwnerCloudPRCommit},
		"land7":  {"copilot-1", projectroi.OwnerCloudPRLanding},
		"subj9":  {"devin-1", projectroi.OwnerCloudPRSubject},
		"human1": {"", projectroi.OwnerNoneNoAIEdits},
		"merge1": {"", projectroi.OwnerNoneMerge},
	}
	for sha, w := range want {
		got := res.Ownership[f.ids[sha]]
		if got.OwnerSessionID != w[0] || got.Reason != w[1] {
			t.Errorf("%s: owner %q reason %q, want %q %q", sha, got.OwnerSessionID, got.Reason, w[0], w[1])
		}
		if w[0] != "" && (len(got.Contributors) != 1 || got.Contributors[0].Files != 2 || got.ShareBasis != projectroi.ShareBasisCloudClaim) {
			t.Errorf("%s: contributors %+v basis %q", sha, got.Contributors, got.ShareBasis)
		}
	}

	// Delivery reads the same fold: the credited commits are AI-touched and
	// carry the cloud session.
	dc, err := f.s.LoadDeliveryCommits(ctx, f.projectID, f.start.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	got := map[int64][]string{}
	for _, c := range dc {
		if !c.AIContributor || c.ForeignAuthor {
			t.Errorf("delivery commit %d: ai %v foreign %v", c.ID, c.AIContributor, c.ForeignAuthor)
		}
		got[c.ID] = c.SessionIDs
	}
	if len(got) != 3 || got[f.ids["bot1"]][0] != "copilot-1" || got[f.ids["subj9"]][0] != "devin-1" {
		t.Fatalf("delivery commits %v", got)
	}
}

// TestCreditCloudCommitsNoLinksIsIdentity: a project no cloud link names is
// returned exactly as folded.
func TestCreditCloudCommitsNoLinksIsIdentity(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	pid, _ := s.UpsertProject(ctx, "/repo/nolinks", "https://github.com/acme/none.git")
	own := map[int64]projectroi.CommitOwnership{1: {CommitID: 1, Reason: projectroi.OwnerNoneNoAIEdits}}
	got, err := s.CreditCloudCommits(ctx, pid, own, []ProjectCommitRow{{ID: 1, SHA: "x", Reachable: true}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[1].Reason != projectroi.OwnerNoneNoAIEdits || got[1].OwnerSessionID != "" {
		t.Fatalf("got %+v", got)
	}
}

// TestRecordCloudSessionLinks pins the writer: normalised remotes, refused
// pointers, idempotent re-reads.
func TestRecordCloudSessionLinks(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		link CloudSessionLink
		want int
	}{
		{"PR on a hosted repository", CloudSessionLink{SessionID: "s", Connector: "copilot-agent", Remote: "https://github.com/Acme/App.git", PRNumber: 3}, 1},
		{"branch only", CloudSessionLink{SessionID: "s", Connector: "cursor-cloud", Remote: "github.com/acme/app", Branch: "cursor/fix-a"}, 1},
		{"no repository", CloudSessionLink{SessionID: "s", Connector: "devin", PRNumber: 3}, 0},
		{"a local path is not a repository", CloudSessionLink{SessionID: "s", Connector: "devin", Remote: "/home/u/app", PRNumber: 3}, 0},
		{"neither PR nor branch", CloudSessionLink{SessionID: "s", Connector: "devin", Remote: "github.com/acme/app"}, 0},
		{"an invalid branch is dropped", CloudSessionLink{SessionID: "s", Connector: "cursor-cloud", Remote: "github.com/acme/app", Branch: "bad branch"}, 0},
		{"no session", CloudSessionLink{Connector: "devin", Remote: "github.com/acme/app", PRNumber: 3}, 0},
	}
	for _, tc := range cases {
		n, err := s.RecordCloudSessionLinks(ctx, []CloudSessionLink{tc.link}, now)
		if err != nil || n != tc.want {
			t.Errorf("%s: wrote %d (%v), want %d", tc.name, n, err, tc.want)
		}
	}
	// A re-read of the same pointer updates last_seen_at, never a second row.
	if _, err := s.RecordCloudSessionLinks(ctx, []CloudSessionLink{{SessionID: "s", Connector: "copilot-agent", Remote: "github.com/acme/app", PRNumber: 3}}, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	links, err := s.ListCloudSessionLinks(ctx, "s")
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 2 || links[0].Remote != "github.com/acme/app" || links[0].PRNumber != 3 || links[1].Branch != "cursor/fix-a" {
		t.Fatalf("links %+v", links)
	}
}

// TestListCloudPRClaimsAndDeliveryRepos: a repository a cloud session
// claimed a PR on is polled by the provider service even with no local
// AI-touched commit.
func TestListCloudPRClaimsAndDeliveryRepos(t *testing.T) {
	t.Parallel()
	f := newCloudCreditFixture(t)
	ctx := context.Background()
	claims, err := f.s.ListCloudPRClaims(ctx, "github.com/acme/app", f.start.Add(-time.Hour), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(claims) != 2 {
		t.Fatalf("claims %+v", claims)
	}
	if later, _ := f.s.ListCloudPRClaims(ctx, "github.com/acme/app", time.Now().Add(time.Hour), 10); len(later) != 0 {
		t.Fatalf("claims from sessions before since: %+v", later)
	}
	repos, err := f.s.ListDeliveryRepos(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 0 {
		t.Fatalf("repos with no project remote row: %+v", repos)
	}
	if err := f.s.UpsertProjectRemote(ctx, delivery.Remote{ProjectID: f.projectID, Name: "origin", URL: "https://github.com/acme/app.git"}); err != nil {
		t.Fatal(err)
	}
	if repos, err = f.s.ListDeliveryRepos(ctx); err != nil || len(repos) != 1 {
		t.Fatalf("repos %+v, %v", repos, err)
	}
	pr, ok, err := f.s.FindPullRequestByNumber(ctx, "GitHub.com", "Acme/App", 7)
	if err != nil || !ok || pr.HeadRef != "copilot/fix" {
		t.Fatalf("FindPullRequestByNumber = %+v %v %v", pr, ok, err)
	}
}
