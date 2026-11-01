package store

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/delivery"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

const (
	dlSlugSentinel  = "SBDLSLUGSENT"
	dlTitleSentinel = "SBDLTITLESENT"
	dlURLSentinel   = "SBDLURLSENT"
	dlRefSentinel   = "SBDLREFSENT"
)

// seedDeliveryWire lands own1 through a merged PR and leaves gone1 in flight,
// with a branch tip and a remote carrying sentinels that must never ship.
func seedDeliveryWire(t *testing.T) deliveryFixture {
	t.Helper()
	f := newDeliveryFixture(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	if err := f.s.UpsertProjectRemote(ctx, delivery.Remote{
		ProjectID: f.projectID, Name: "origin",
		URL: "https://github.com/acme/" + dlSlugSentinel + ".git", FetchHeadAt: now.Add(-2 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	linkID, err := f.s.CreateProviderLink(ctx, delivery.ProviderLink{Provider: delivery.ProviderGitHub, Host: "github.com", AuthMode: "token", KeyName: "link.1.token"})
	if err != nil {
		t.Fatal(err)
	}
	prID, err := f.s.UpsertPullRequest(ctx, delivery.PullRequest{
		LinkID: linkID, Provider: delivery.ProviderGitHub, Host: "github.com", RepoSlug: "acme/" + dlSlugSentinel, Number: 77,
		Title: dlTitleSentinel, URL: "https://github.com/acme/" + dlURLSentinel, State: delivery.PRMerged,
		MergeMethod: delivery.MergeSquash, CreatedAt: now.Add(-3 * time.Hour), MergedAt: now.Add(-time.Hour), FetchedAt: now,
	}, []delivery.PRCommit{{SHA: "own1"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.s.UpsertCommitLandings(ctx, []delivery.Landing{
		{
			CommitID: f.ids["own1"], Status: delivery.StatusLanded, Kind: delivery.KindSquash, PRID: prID, PRNumber: 77,
			RuleID: "P1", RuleVersion: 1, Source: delivery.SourceProvider, EvaluatedAt: now, SessionIDs: []string{"wA"},
		},
		{CommitID: f.ids["gone1"], Status: delivery.StatusInFlight, RuleID: "L8", RuleVersion: 1, EvaluatedAt: now},
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.s.UpsertBranchTips(ctx, []delivery.BranchTip{{ProjectID: f.projectID, RefName: dlRefSentinel, TipSHA: "t", ObservedAt: now}}); err != nil {
		t.Fatal(err)
	}
	return f
}

// TestSelectDeliveryWireRowsPrivacy pins the D-689 posture: day counts from
// every node, PR identity only under raw content, and a branch name, a
// remote URL, a mirror path or a keychain name never.
func TestSelectDeliveryWireRowsPrivacy(t *testing.T) {
	t.Parallel()
	f := seedDeliveryWire(t)
	ctx := context.Background()
	since := time.Now().UTC().AddDate(0, 0, -deliveryOrgWindowDays)

	days, prs, err := f.s.SelectDeliveryWireRows(ctx, ScopeOptions{}, since, false)
	if err != nil {
		t.Fatalf("SelectDeliveryWireRows: %v", err)
	}
	if len(prs) != 0 {
		t.Fatalf("metadata posture shipped PR rows: %+v", prs)
	}
	raw, _ := json.Marshal(days)
	for _, s := range []string{dlSlugSentinel, dlTitleSentinel, dlURLSentinel, dlRefSentinel, "link.1.token", "own1", "gone1"} {
		if strings.Contains(string(raw), s) {
			t.Fatalf("metadata day rows carry %q: %s", s, raw)
		}
	}
	var commits, landed, squash, merged, opened int64
	for _, d := range days {
		commits += d.AICommits
		landed += d.AICommitsLanded
		squash += d.LandedSquash
		merged += d.PRsMerged
		opened += d.PRsOpened
		if d.Source != "provider" || d.RuleVersion != delivery.RuleVersion || d.ProjectRootHash == "" || d.FetchAgeBucket == delivery.AgeUnknown {
			t.Errorf("day row = %+v", d)
		}
	}
	if commits != 2 || landed != 1 || squash != 1 || merged != 1 || opened != 1 {
		t.Fatalf("day counts: commits=%d landed=%d squash=%d merged=%d opened=%d (%+v)", commits, landed, squash, merged, opened, days)
	}

	_, prs, err = f.s.SelectDeliveryWireRows(ctx, ScopeOptions{}, since, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(prs) != 1 {
		t.Fatalf("raw posture PR rows = %+v", prs)
	}
	p := prs[0]
	if p.Number != 77 || p.Title != dlTitleSentinel || p.RepoSlug != "acme/"+dlSlugSentinel || p.PRState != "merged" ||
		p.MergeMethod != "squash" || p.RepoSlugHash != delivery.RepoSlugHash("github.com", "acme/"+dlSlugSentinel) ||
		len(p.CommitSHAHashes) != 1 || p.CommitSHAHashes[0] != sha256Hex("own1") {
		t.Fatalf("PR row = %+v", p)
	}
	raw, _ = json.Marshal(prs)
	for _, s := range []string{dlRefSentinel, "link.1.token", `"own1"`} {
		if strings.Contains(string(raw), s) {
			t.Fatalf("raw PR rows carry %q: %s", s, raw)
		}
	}
}

// TestSelectUnpushedSinceDeliveryWire runs the real push seam: the day rows
// ride every posture, the PR rows only the raw ones.
func TestSelectUnpushedSinceDeliveryWire(t *testing.T) {
	t.Parallel()
	f := seedDeliveryWire(t)
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		share  ShareOptions
		wantPR bool
	}{
		{"metadata", ShareOptions{}, false},
		{"full_content", ShareOptions{FullContent: true}, true},
		{"admin_managed", ShareOptions{AdminManaged: true}, true},
	} {
		batch, err := f.s.SelectUnpushedSince(ctx, PushCursor{}, 1<<20, "org-1", "dev@x", tc.share, ScopeOptions{})
		if err != nil {
			t.Fatalf("%s: SelectUnpushedSince: %v", tc.name, err)
		}
		if len(batch.DeliveryDays) == 0 || batch.DeliveryDays[0].OrgID != "org-1" {
			t.Fatalf("%s: delivery days = %+v", tc.name, batch.DeliveryDays)
		}
		if (len(batch.PullRequests) > 0) != tc.wantPR {
			t.Fatalf("%s: PR rows = %+v", tc.name, batch.PullRequests)
		}
		raw, _ := json.Marshal(batch)
		if !tc.wantPR && (strings.Contains(string(raw), dlTitleSentinel) || strings.Contains(string(raw), dlURLSentinel)) {
			t.Fatalf("%s: PR title or URL in the metadata push", tc.name)
		}
		if strings.Contains(string(raw), dlRefSentinel) {
			t.Fatalf("%s: branch name in the push", tc.name)
		}
	}
}

// TestDeliveryWireRowsCounting pins the pure counting rule.
func TestDeliveryWireRowsCounting(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	d1 := now.Add(-48 * time.Hour)
	in := deliveryWireInput{
		since: now.AddDate(0, 0, -30), now: now,
		rootHash: map[int64]string{1: "root"},
		landings: map[int64][]landingWithCommit{1: {
			{ProjectID: 1, CommittedAt: d1, Landing: delivery.Landing{Status: delivery.StatusLanded, Kind: delivery.KindExactSHA}},
			{ProjectID: 1, CommittedAt: d1, Landing: delivery.Landing{Status: delivery.StatusLanded, Kind: delivery.KindRebase}},
			{ProjectID: 1, CommittedAt: d1, Landing: delivery.Landing{Status: delivery.StatusPushed}},
			{ProjectID: 1, CommittedAt: d1, Landing: delivery.Landing{Status: delivery.StatusAbandoned}},
			{ProjectID: 1, CommittedAt: now, Landing: delivery.Landing{Status: delivery.StatusInFlight}},
		}},
		prs: map[int64][]wirePR{1: {
			{ProjectID: 1, PR: delivery.PullRequest{State: delivery.PROpen, Readiness: delivery.ReadyToMerge, CreatedAt: d1}},
			{ProjectID: 1, PR: delivery.PullRequest{State: delivery.PROpen, Readiness: delivery.ReadyChecksFail, CreatedAt: d1}},
			{ProjectID: 1, PR: delivery.PullRequest{State: delivery.PRDraft}},
			// Unknown readiness is neither ready nor blocked (delivery.PRBucket).
			{ProjectID: 1, PR: delivery.PullRequest{State: delivery.PROpen, Readiness: delivery.ReadyUnknown}},
			{ProjectID: 1, PR: delivery.PullRequest{State: delivery.PROpen}},
			{ProjectID: 1, PR: delivery.PullRequest{State: delivery.PRClosedUnmerged, ClosedAt: d1}},
			{ProjectID: 1, PR: delivery.PullRequest{State: delivery.PRMerged, CreatedAt: d1.Add(-time.Hour), MergedAt: d1}},
			{ProjectID: 1, PR: delivery.PullRequest{State: delivery.PRMerged, CreatedAt: d1.Add(-3 * time.Hour), MergedAt: d1}},
		}},
	}
	days, prs := deliveryWireRows(in, []int64{1})
	if len(prs) != 0 {
		t.Fatalf("PR rows without shipRaw: %+v", prs)
	}
	by := map[string]orgcontract.DeliveryDayRow{}
	for _, d := range days {
		by[d.Day] = d
	}
	a := by[d1.Format("2006-01-02")]
	if a.AICommits != 4 || a.AICommitsLanded != 2 || a.LandedExact != 1 || a.LandedPatch != 1 || a.AICommitsPushed != 1 ||
		a.AICommitsAbandoned != 1 || a.PRsOpened != 4 || a.PRsMerged != 2 || a.PRsClosedUnmerged != 1 ||
		a.MergeSamples != 2 || a.MergeSecondsP50 != 3600 || a.MergeSecondsP75 != 3*3600 {
		t.Fatalf("day %s = %+v", d1.Format("2006-01-02"), a)
	}
	b := by[now.Format("2006-01-02")]
	if b.AICommits != 1 || b.PRsOpenReady != 1 || b.PRsOpenBlocked != 1 || b.PRsDraft != 1 || b.Source != "provider" {
		t.Fatalf("today = %+v", b)
	}
	// No provider PRs and no evidence: local, unknown freshness.
	in.prs = nil
	days, _ = deliveryWireRows(in, []int64{1})
	if days[0].Source != "local" || days[0].FetchAgeBucket != delivery.AgeUnknown {
		t.Fatalf("local-only day = %+v", days[0])
	}
}
