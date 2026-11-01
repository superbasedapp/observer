package store

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/delivery"
)

// deliveryFixture is commitOwnershipWireFixture (own1 owned by wA with wB
// contributing, human1 human-only, gone1 unreachable, merge1 a merge, old1
// ten days old) plus the ids the delivery tests need.
type deliveryFixture struct {
	s         *Store
	projectID int64
	ids       map[string]int64
}

func newDeliveryFixture(t *testing.T) deliveryFixture {
	t.Helper()
	s, root := commitOwnershipWireFixture(t)
	ctx := context.Background()
	pid, err := s.ProjectIDForRoot(ctx, root)
	if err != nil {
		t.Fatalf("ProjectIDForRoot: %v", err)
	}
	f := deliveryFixture{s: s, projectID: pid, ids: map[string]int64{}}
	for _, sha := range coWireFixtureSHAs {
		var id int64
		if err := s.db.QueryRowContext(ctx, `SELECT id FROM project_commits WHERE sha = ?`, sha).Scan(&id); err != nil {
			t.Fatalf("commit id %s: %v", sha, err)
		}
		f.ids[sha] = id
	}
	return f
}

func TestSetCommitPatchFingerprint(t *testing.T) {
	t.Parallel()
	f := newDeliveryFixture(t)
	ctx := context.Background()
	cases := []struct {
		fp, state    string
		wantStoredFP string
		wantStoredSt string
	}{
		{"abc", delivery.FPOK, "abc", delivery.FPOK},
		{"abc", delivery.FPTooLarge, "", delivery.FPTooLarge},
		{"", delivery.FPError, "", delivery.FPError},
		{"", "", "", delivery.FPPending},
	}
	for _, tc := range cases {
		if err := f.s.SetCommitPatchFingerprint(ctx, f.ids["own1"], tc.fp, tc.state); err != nil {
			t.Fatalf("SetCommitPatchFingerprint: %v", err)
		}
		var fp *string
		var st string
		if err := f.s.db.QueryRowContext(ctx, `SELECT patch_fp, patch_fp_state FROM project_commits WHERE id = ?`, f.ids["own1"]).Scan(&fp, &st); err != nil {
			t.Fatal(err)
		}
		got := ""
		if fp != nil {
			got = *fp
		}
		if got != tc.wantStoredFP || st != tc.wantStoredSt {
			t.Errorf("(%q, %q) stored (%q, %q), want (%q, %q)", tc.fp, tc.state, got, st, tc.wantStoredFP, tc.wantStoredSt)
		}
	}
}

func TestProjectRemotesNeverStoreCredentials(t *testing.T) {
	t.Parallel()
	f := newDeliveryFixture(t)
	ctx := context.Background()
	const token = "ghp_SEEDEDSTORETOKEN0123456789"
	err := f.s.UpsertProjectRemote(ctx, delivery.Remote{
		ProjectID: f.projectID, Name: "origin", URL: "https://user:" + token + "@github.com/Acme/Widget.git",
		DefaultBranch: "main", DefaultRefSHA: "abc", FetchHeadAt: time.Now().UTC().Add(-time.Hour),
	})
	if err != nil {
		t.Fatalf("UpsertProjectRemote: %v", err)
	}
	if err := f.s.UpsertProjectRemote(ctx, delivery.Remote{ProjectID: f.projectID, Name: "local", URL: "/srv/mirror.git"}); err != nil {
		t.Fatalf("UpsertProjectRemote(local): %v", err)
	}
	rs, err := f.s.LoadProjectRemotes(ctx, f.projectID)
	if err != nil {
		t.Fatalf("LoadProjectRemotes: %v", err)
	}
	if len(rs) != 2 {
		t.Fatalf("remotes = %+v", rs)
	}
	for _, r := range rs {
		raw, _ := json.Marshal(r)
		if strings.Contains(string(raw), token) {
			t.Fatalf("credential stored: %s", raw)
		}
	}
	origin := rs[1]
	if origin.Name != "origin" || origin.URL != "https://github.com/Acme/Widget.git" || origin.Host != "github.com" ||
		origin.Provider != delivery.ProviderGitHub || origin.RepoSlug != "Acme/Widget" || origin.FetchHeadAt.IsZero() {
		t.Fatalf("origin = %+v", origin)
	}
	if rs[0].URL != "" || rs[0].Provider != delivery.ProviderUnknown {
		t.Fatalf("local path remote = %+v", rs[0])
	}
	// Not on the poll list until the project has an evaluated AI commit.
	repos, err := f.s.ListDeliveryRepos(ctx)
	if err != nil || len(repos) != 0 {
		t.Fatalf("ListDeliveryRepos before landings = %+v, %v", repos, err)
	}
	if err := f.s.UpsertCommitLandings(ctx, []delivery.Landing{{CommitID: f.ids["own1"], Status: delivery.StatusInFlight, EvaluatedAt: time.Now()}}); err != nil {
		t.Fatal(err)
	}
	repos, err = f.s.ListDeliveryRepos(ctx)
	if err != nil || len(repos) != 2 {
		t.Fatalf("ListDeliveryRepos after landings = %+v, %v", repos, err)
	}
}

func TestDeliveryCommitsAndLandings(t *testing.T) {
	t.Parallel()
	f := newDeliveryFixture(t)
	ctx := context.Background()
	since := time.Now().UTC().Add(-7 * 24 * time.Hour)

	commits, err := f.s.LoadDeliveryCommits(ctx, f.projectID, since)
	if err != nil {
		t.Fatalf("LoadDeliveryCommits: %v", err)
	}
	if len(commits) != 1 || commits[0].SHA != "own1" || !commits[0].AIContributor ||
		commits[0].PatchFPState != delivery.FPPending || strings.Join(commits[0].SessionIDs, ",") != "wA,wB" {
		t.Fatalf("AI commits = %+v", commits)
	}

	// gone1 fell out of HEAD, so Ownership drops it; once it has a landing it
	// stays in the evaluated set with its stored contributors.
	now := time.Now().UTC().Truncate(time.Second)
	landings := []delivery.Landing{
		{
			CommitID: f.ids["own1"], Status: delivery.StatusLanded, Kind: delivery.KindSquash, Confidence: delivery.ConfHigh,
			RuleID: "L3", RuleVersion: 1, LandingSHA: "sq", PRNumber: 12, Source: delivery.SourceUserRefs,
			FirstPushedAt: now.Add(-time.Hour), LandedAt: now, LandedAtSource: delivery.LandedAtMergeCommit, EvaluatedAt: now,
			SessionIDs: []string{"wA", "wB"},
		},
		{CommitID: f.ids["gone1"], Status: delivery.StatusInFlight, RuleID: "L8", RuleVersion: 1, EvaluatedAt: now, SessionIDs: []string{"wA"}},
	}
	if err := f.s.UpsertCommitLandings(ctx, landings); err != nil {
		t.Fatalf("UpsertCommitLandings: %v", err)
	}
	// A re-evaluation without contributors keeps the stored list.
	if err := f.s.UpsertCommitLandings(ctx, []delivery.Landing{{
		CommitID: f.ids["gone1"], Status: delivery.StatusAbandoned,
		AbandonReason: delivery.AbandonDropped, RuleID: "L7", RuleVersion: 1, EvaluatedAt: now,
	}}); err != nil {
		t.Fatal(err)
	}
	commits, err = f.s.LoadDeliveryCommits(ctx, f.projectID, since)
	if err != nil {
		t.Fatal(err)
	}
	if len(commits) != 2 || commits[0].SHA != "gone1" || commits[0].Reachable || strings.Join(commits[0].SessionIDs, ",") != "wA" {
		t.Fatalf("after landings = %+v", commits)
	}

	got, err := f.s.LoadProjectLandings(ctx, f.projectID, since, now.Add(time.Hour))
	if err != nil || len(got) != 2 {
		t.Fatalf("LoadProjectLandings = %+v, %v", got, err)
	}
	byID := map[int64]delivery.Landing{}
	for _, l := range got {
		byID[l.CommitID] = l
	}
	own := byID[f.ids["own1"]]
	if own.Status != delivery.StatusLanded || own.Kind != delivery.KindSquash || own.PRNumber != 12 || own.PRID != 0 ||
		!own.LandedAt.Equal(now) || own.LandedAtSource != delivery.LandedAtMergeCommit || own.RuleID != "L3" {
		t.Fatalf("own1 landing = %+v", own)
	}
	if gone := byID[f.ids["gone1"]]; gone.Status != delivery.StatusAbandoned || len(gone.SessionIDs) != 1 {
		t.Fatalf("gone1 landing = %+v", gone)
	}

	// The session view: wA contributed to both; it owns own1.
	sl, err := f.s.LoadSessionLandings(ctx, "wA")
	if err != nil {
		t.Fatalf("LoadSessionLandings: %v", err)
	}
	if len(sl) != 2 {
		t.Fatalf("session landings = %+v", sl)
	}
	for _, x := range sl {
		if !x.Evaluated {
			t.Errorf("%s not evaluated", x.SHA)
		}
		if x.SHA == "own1" && (!x.Owner || x.Landing.Status != delivery.StatusLanded) {
			t.Errorf("own1 = %+v", x)
		}
	}
	sl, err = f.s.LoadSessionLandings(ctx, "wB")
	if err != nil || len(sl) != 1 || sl[0].SHA != "own1" || sl[0].Owner {
		t.Fatalf("wB landings = %+v, %v", sl, err)
	}
	if sl, err := f.s.LoadSessionLandings(ctx, "no-such-session"); err != nil || len(sl) != 0 {
		t.Fatalf("unknown session = %+v, %v", sl, err)
	}
}

func TestProviderLinksAndPullRequests(t *testing.T) {
	t.Parallel()
	f := newDeliveryFixture(t)
	ctx := context.Background()

	id1, err := f.s.CreateProviderLink(ctx, delivery.ProviderLink{Provider: delivery.ProviderGitHub, Host: "GitHub.com", AuthMode: "token", KeyName: "link.1.token"})
	if err != nil {
		t.Fatalf("CreateProviderLink: %v", err)
	}
	id2, err := f.s.CreateProviderLink(ctx, delivery.ProviderLink{Provider: delivery.ProviderGitHub, Host: "github.com", AuthMode: "gh_cli"})
	if err != nil || id2 != id1 {
		t.Fatalf("reconnect id = %d (%v), want %d", id2, err, id1)
	}
	okAt := time.Now().UTC().Truncate(time.Second)
	if err := f.s.UpdateProviderLinkStatus(ctx, id1, "ok", "", "", okAt, okAt.Add(10*time.Minute), 0); err != nil {
		t.Fatal(err)
	}
	if err := f.s.UpdateProviderLinkStatus(ctx, id1, "rate_limited", "rate_limited", "token=ghp_SECRETVALUE123456789 limit hit", time.Time{}, okAt.Add(time.Hour), 2); err != nil {
		t.Fatal(err)
	}
	if err := f.s.UpdateProviderLinkStatus(ctx, 9999, "ok", "", "", okAt, okAt, 0); err == nil {
		t.Fatal("updating a missing link succeeded")
	}
	links, err := f.s.ListProviderLinks(ctx)
	if err != nil || len(links) != 1 {
		t.Fatalf("ListProviderLinks = %+v, %v", links, err)
	}
	l := links[0]
	if l.AuthMode != "gh_cli" || l.Status != "rate_limited" || !l.LastOKAt.Equal(okAt) || l.ConsecutiveFailures != 2 ||
		strings.Contains(l.LastError, "ghp_SECRETVALUE") {
		t.Fatalf("link = %+v", l)
	}

	long := strings.Repeat("t", 800)
	pr := delivery.PullRequest{
		LinkID: id1, Provider: delivery.ProviderGitHub, Host: "github.com", RepoSlug: "Acme/Widget", Number: 12,
		Title: long, URL: "https://github.com/Acme/Widget/pull/12", State: delivery.PROpen, Readiness: delivery.ReadyConflicts,
		Facets: delivery.Facets{Conflicts: delivery.ConflictsPresent}, RawState: "open/dirty", HeadSHA: "head12", BaseRef: "main",
		CreatedAt: okAt.Add(-48 * time.Hour),
	}
	prID, err := f.s.UpsertPullRequest(ctx, pr, []delivery.PRCommit{{SHA: "own1", Position: 0, PatchFP: "fp-own"}, {SHA: "x2", Position: 1}})
	if err != nil {
		t.Fatalf("UpsertPullRequest: %v", err)
	}
	// A list refresh (nil commits) keeps the list; a state change lands.
	pr.State, pr.Readiness = delivery.PRMerged, ""
	pr.MergedAt = okAt
	if again, err := f.s.UpsertPullRequest(ctx, pr, nil); err != nil || again != prID {
		t.Fatalf("re-upsert id = %d, %v", again, err)
	}
	pcs, err := f.s.LoadPullRequestCommits(ctx, prID)
	if err != nil || len(pcs) != 2 || pcs[0].PatchFP != "fp-own" {
		t.Fatalf("PR commits = %+v, %v", pcs, err)
	}
	// Replacing keeps a known fingerprint; SetPRCommitPatchFingerprint fills one.
	if _, err := f.s.UpsertPullRequest(ctx, pr, []delivery.PRCommit{{SHA: "own1"}, {SHA: "x3", Position: 1}}); err != nil {
		t.Fatal(err)
	}
	if err := f.s.SetPRCommitPatchFingerprint(ctx, prID, "x3", "fp-x3"); err != nil {
		t.Fatal(err)
	}
	pcs, _ = f.s.LoadPullRequestCommits(ctx, prID)
	if len(pcs) != 2 || pcs[0].SHA != "own1" || pcs[0].PatchFP != "fp-own" || pcs[1].PatchFP != "fp-x3" {
		t.Fatalf("replaced PR commits = %+v", pcs)
	}

	since := time.Now().UTC().Add(-7 * 24 * time.Hour)
	prs, err := f.s.LoadProjectPullRequests(ctx, f.projectID, since)
	if err != nil || len(prs) != 1 {
		t.Fatalf("LoadProjectPullRequests = %+v, %v", prs, err)
	}
	got := prs[0]
	if got.ID != prID || got.State != delivery.PRMerged || len(got.Title) > prTitleMaxBytes ||
		got.Facets.Conflicts != delivery.ConflictsPresent || !got.MergedAt.Equal(okAt) {
		t.Fatalf("stored PR = %+v", got)
	}
	for _, sha := range []string{"own1", "head12"} {
		found, err := f.s.FindPullRequestsForSHA(ctx, sha)
		if err != nil || len(found) != 1 || found[0].ID != prID {
			t.Fatalf("FindPullRequestsForSHA(%s) = %+v, %v", sha, found, err)
		}
	}
	if found, _ := f.s.FindPullRequestsForSHA(ctx, "nope"); len(found) != 0 {
		t.Fatalf("unknown sha found %+v", found)
	}

	// A landing that names the PR loses the link when the connection goes.
	if err := f.s.UpsertCommitLandings(ctx, []delivery.Landing{{
		CommitID: f.ids["own1"], Status: delivery.StatusLanded,
		PRID: prID, PRNumber: 12, RuleID: "P1", RuleVersion: 1, EvaluatedAt: okAt,
	}}); err != nil {
		t.Fatal(err)
	}
	sl, err := f.s.LoadSessionLandings(ctx, "wA")
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range sl {
		if x.SHA == "own1" && (x.PR == nil || x.PR.Number != 12) {
			t.Fatalf("session landing PR = %+v", x)
		}
	}
	if err := f.s.DeleteProviderLink(ctx, id1); err != nil {
		t.Fatalf("DeleteProviderLink: %v", err)
	}
	if links, _ := f.s.ListProviderLinks(ctx); len(links) != 0 {
		t.Fatalf("links after delete = %+v", links)
	}
	if prs, _ := f.s.LoadProjectPullRequests(ctx, f.projectID, since); len(prs) != 0 {
		t.Fatalf("PRs after delete = %+v", prs)
	}
	ls, _ := f.s.LoadProjectLandings(ctx, f.projectID, since, time.Now().Add(time.Hour))
	if len(ls) != 1 || ls[0].PRID != 0 || ls[0].Status != delivery.StatusLanded {
		t.Fatalf("landing after link delete = %+v", ls)
	}
}

func TestDeliveryMirrorsSettingsAndTips(t *testing.T) {
	t.Parallel()
	f := newDeliveryFixture(t)
	ctx := context.Background()

	if _, err := f.s.UpsertDeliveryMirror(ctx, delivery.Mirror{URL: "/local/path"}); err == nil {
		t.Fatal("a non-remote mirror URL was accepted")
	}
	id, err := f.s.UpsertDeliveryMirror(ctx, delivery.Mirror{URL: "https://tok:secret@gitlab.com/g/p.git", Path: "/m/x.git", Status: "ok", SizeBytes: 10})
	if err != nil {
		t.Fatalf("UpsertDeliveryMirror: %v", err)
	}
	again, err := f.s.UpsertDeliveryMirror(ctx, delivery.Mirror{URL: "https://gitlab.com/g/p.git", Path: "/m/x.git", Status: "ok", SizeBytes: 20})
	if err != nil || again != id {
		t.Fatalf("re-upsert = %d, %v", again, err)
	}
	ms, err := f.s.ListDeliveryMirrors(ctx)
	if err != nil || len(ms) != 1 || ms[0].URL != "https://gitlab.com/g/p.git" || ms[0].SizeBytes != 20 ||
		ms[0].URLHash != delivery.MirrorKey("https://gitlab.com/g/p.git") {
		t.Fatalf("mirrors = %+v, %v", ms, err)
	}
	if err := f.s.DeleteDeliveryMirror(ctx, id); err != nil {
		t.Fatal(err)
	}
	if ms, _ := f.s.ListDeliveryMirrors(ctx); len(ms) != 0 {
		t.Fatalf("mirrors after delete = %+v", ms)
	}

	ps, err := f.s.GetDeliveryProjectSettings(ctx, f.projectID)
	if err != nil || ps.MirrorEnabled || ps.ScheduleMinutes != 0 || ps.ProjectID != f.projectID {
		t.Fatalf("default settings = %+v, %v", ps, err)
	}
	if err := f.s.SetDeliveryProjectSettings(ctx, delivery.ProjectSettings{ProjectID: f.projectID, MirrorEnabled: true, ScheduleMinutes: 30}); err != nil {
		t.Fatal(err)
	}
	ps, _ = f.s.GetDeliveryProjectSettings(ctx, f.projectID)
	all, _ := f.s.ListDeliveryProjectSettings(ctx)
	if !ps.MirrorEnabled || ps.ScheduleMinutes != 30 || len(all) != 1 {
		t.Fatalf("settings = %+v, all = %+v", ps, all)
	}

	tip := delivery.BranchTip{
		ProjectID: f.projectID, RefName: "refs/heads/TICKET-123-secret", TipSHA: "t1",
		MemberSHAs: []string{"own1"}, Files: []string{"a.go"}, RangeFP: "rf", RangeFPState: delivery.FPOK, ObservedAt: time.Now(),
	}
	if err := f.s.UpsertBranchTips(ctx, []delivery.BranchTip{tip}); err != nil {
		t.Fatal(err)
	}
	tip.TipSHA = "t2"
	if err := f.s.UpsertBranchTips(ctx, []delivery.BranchTip{tip}); err != nil {
		t.Fatal(err)
	}
	tips, err := f.s.LoadBranchTips(ctx, f.projectID)
	if err != nil || len(tips) != 1 || tips[0].TipSHA != "t2" || tips[0].RefNameHash != sha256Hex(tip.RefName) ||
		len(tips[0].MemberSHAs) != 1 || tips[0].RangeFPState != delivery.FPOK {
		t.Fatalf("tips = %+v, %v", tips, err)
	}
}
