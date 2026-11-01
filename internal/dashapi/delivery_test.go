package dashapi

import (
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/delivery"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestComposeProjectDeliverySource is one case per row of the source
// rules: no remote, the user's fetches, a mirror (only when opted in), a
// code host, and a code host whose link stopped (problem + stale PRs).
func TestComposeProjectDeliverySource(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	gh := delivery.Remote{Name: "origin", URL: "https://github.com/acme/app.git", Host: "github.com", Provider: delivery.ProviderGitHub, RepoSlug: "acme/app", DefaultBranch: "main", FetchHeadAt: now.Add(-2 * time.Hour)}
	gl := delivery.Remote{Name: "origin", URL: "https://gitlab.com/acme/app.git", Host: "gitlab.com", Provider: delivery.ProviderGitLab, RepoSlug: "acme/app", DefaultBranch: "main", FetchHeadAt: now.Add(-48 * time.Hour)}
	mirror := delivery.Mirror{ID: 3, URLHash: delivery.MirrorKey(gl.URL), URL: gl.URL, Status: "ok", LastRefreshAt: now.Add(-10 * time.Minute)}
	okLink := delivery.ProviderLink{ID: 1, Provider: delivery.ProviderGitHub, Host: "github.com", AuthMode: "token", AccountLogin: "dev", Status: "ok", LastOKAt: now.Add(-4 * time.Minute)}
	badLink := okLink
	badLink.Status, badLink.LastError = "auth_failed", "refused"

	cases := []struct {
		name         string
		in           ProjectDeliveryInput
		wantKind     string
		wantLinked   bool
		wantProblem  bool
		wantEligible bool
	}{
		{"no remote", ProjectDeliveryInput{}, "none", false, false, false},
		{"user refs", ProjectDeliveryInput{Remotes: []delivery.Remote{gh}}, "user_refs", false, false, true},
		{"mirror present but not opted in", ProjectDeliveryInput{Remotes: []delivery.Remote{gl}, Mirrors: []delivery.Mirror{mirror}}, "user_refs", false, false, true},
		{"mirror opted in", ProjectDeliveryInput{Remotes: []delivery.Remote{gl}, Mirrors: []delivery.Mirror{mirror}, Settings: delivery.ProjectSettings{MirrorEnabled: true}}, "mirror", false, false, true},
		{"code host", ProjectDeliveryInput{Remotes: []delivery.Remote{gh}, Links: []delivery.ProviderLink{okLink}}, "provider", true, false, false},
		{"code host stopped", ProjectDeliveryInput{Remotes: []delivery.Remote{gh}, Links: []delivery.ProviderLink{badLink}}, "provider", true, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.in.Now = now
			got := ComposeProjectDelivery(tc.in)
			if got.Source.Kind != tc.wantKind || got.ProviderLinked != tc.wantLinked || (got.LinkProblem != nil) != tc.wantProblem || got.MirrorEligible != tc.wantEligible {
				t.Fatalf("source=%+v linked=%v problem=%+v eligible=%v", got.Source, got.ProviderLinked, got.LinkProblem, got.MirrorEligible)
			}
			if !tc.wantLinked && got.Summary.PRMergeRate.Known {
				t.Fatal("PR merge rate known without a code host")
			}
		})
	}
}

// TestComposeProjectDeliveryPRs: a PR shows only when it holds a window
// AI commit; its rows are stale when its link is not healthy; the commit
// held by no PR lands in NotInPR.
func TestComposeProjectDeliveryPRs(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	link := delivery.ProviderLink{ID: 1, Provider: delivery.ProviderGitHub, Host: "github.com", Status: "rate_limited"}
	in := ProjectDeliveryInput{
		Now:     now,
		Remotes: []delivery.Remote{{Name: "origin", Host: "github.com", Provider: delivery.ProviderGitHub, RepoSlug: "acme/app"}},
		Links:   []delivery.ProviderLink{link},
		Landings: []delivery.Landing{
			{CommitID: 1, Status: delivery.StatusInPR, PRID: 10},
			{CommitID: 2, Status: delivery.StatusPushed},
		},
		Ownership: store.CommitOwnershipResult{Commits: []store.ProjectCommitRow{
			{ID: 1, SHA: "aaa", CommittedAt: now.Add(-time.Hour)},
			{ID: 2, SHA: "bbb", CommittedAt: now.Add(-2 * time.Hour)},
		}},
		PRs: []delivery.PullRequest{
			{ID: 10, LinkID: 1, Number: 5, State: delivery.PROpen, Readiness: delivery.ReadyConflicts, URL: "https://github.com/acme/app/pull/5"},
			{ID: 11, LinkID: 1, Number: 6, State: delivery.PRMerged, URL: "javascript:alert(1)"},
		},
		PRCommits: map[int64][]delivery.PRCommit{11: {{SHA: "zzz"}}},
	}
	got := ComposeProjectDelivery(in)
	if len(got.PullRequests) != 1 || got.PullRequests[0].Number != 5 || !got.PullRequests[0].Stale || got.PullRequests[0].Bucket != "open_blocked" {
		t.Fatalf("PRs = %+v", got.PullRequests)
	}
	if got.NotInPRTotal != 1 || got.NotInPR[0].SHA != "bbb" {
		t.Fatalf("not in PR = %+v", got.NotInPR)
	}
	if got.LinkProblem == nil || got.LinkProblem.Status != "rate_limited" {
		t.Fatalf("link problem = %+v", got.LinkProblem)
	}
	if w := DeliveryPRWire(in.PRs[1], false); w.URL != "" {
		t.Fatalf("non-https URL passed through: %q", w.URL)
	}
}

func TestValidDeliverySchedule(t *testing.T) {
	for _, tc := range []struct {
		m  int
		ok bool
	}{{0, true}, {29, false}, {30, true}, {DeliveryMaxScheduleMinutes, true}, {DeliveryMaxScheduleMinutes + 1, false}} {
		if ValidDeliverySchedule(tc.m) != tc.ok {
			t.Errorf("ValidDeliverySchedule(%d) != %v", tc.m, tc.ok)
		}
	}
}
