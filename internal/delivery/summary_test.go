package delivery

import (
	"testing"
	"time"
)

func TestFetchAgeBucket(t *testing.T) {
	t.Parallel()
	now := evalNow
	cases := []struct {
		at   time.Time
		want string
	}{
		{time.Time{}, AgeUnknown},
		{now.Add(-30 * time.Minute), AgeUnder1h},
		{now.Add(-5 * time.Hour), AgeUnder24h},
		{now.Add(-3 * 24 * time.Hour), AgeUnder7d},
		{now.Add(-9 * 24 * time.Hour), AgeStale},
	}
	for _, tc := range cases {
		if got := FetchAgeBucket(tc.at, now); got != tc.want {
			t.Errorf("FetchAgeBucket(%v) = %q, want %q", tc.at, got, tc.want)
		}
	}
	if got := StaleCaveat(now.Add(-9*24*time.Hour), now); got != "based on a fetch 9 days old" {
		t.Errorf("StaleCaveat = %q", got)
	}
	if got := StaleCaveat(now.Add(-time.Hour), now); got != "" {
		t.Errorf("fresh StaleCaveat = %q", got)
	}
}

func TestSummariseUnknownIsNeverZero(t *testing.T) {
	t.Parallel()
	s := Summarise(SummaryInput{Now: evalNow})
	for name, r := range map[string]Rate{"accepted": s.AcceptedWorkRate, "share": s.LandedShare, "pr": s.PRMergeRate} {
		if r.Known || r.UnknownReason == "" {
			t.Errorf("%s rate on empty input = %+v, want unknown with a reason", name, r)
		}
	}
	if s.PRMergeRate.UnknownReason != UnknownNoProvider || s.OpenMergeable.Known || s.BlockedKnown {
		t.Errorf("provider metrics without a provider: %+v / %+v", s.PRMergeRate, s.OpenMergeable)
	}
	if s.TimeToMerge.Known || s.Funnel.Known || s.FetchAge != AgeUnknown {
		t.Errorf("empty summary: %+v", s)
	}
}

func TestSummarise(t *testing.T) {
	t.Parallel()
	day := evalNow.Add(-24 * time.Hour)
	landings := []Landing{
		{CommitID: 1, Status: StatusLanded, Kind: KindExactSHA, LandedAt: day.Add(2 * time.Hour), LandedAtSource: LandedAtFirstSeen},
		{CommitID: 2, Status: StatusLanded, Kind: KindSquash, PRNumber: 5, LandedAt: day.Add(4 * time.Hour), LandedAtSource: LandedAtMergeCommit},
		{CommitID: 3, Status: StatusLanded, Kind: KindRebase},
		{CommitID: 4, Status: StatusAbandoned, AbandonReason: AbandonDropped},
		{CommitID: 5, Status: StatusInPR, PRID: 9},
		{CommitID: 6, Status: StatusLikelyLanded, Kind: KindContent},
		{CommitID: 7, Status: StatusInFlight},
	}
	committed := map[int64]time.Time{1: day, 2: day}
	prs := []PullRequest{
		{State: PRMerged, CreatedAt: day, MergedAt: day.Add(time.Hour)},
		{State: PRMerged, CreatedAt: day, MergedAt: day.Add(3 * time.Hour)},
		{State: PRClosedUnmerged},
		{State: PROpen, Readiness: ReadyToMerge},
		{State: PROpen, Readiness: ReadyConflicts},
		{State: PRDraft},
	}
	prompts := []PromptDelivery{{}, {CommitIDs: []int64{7}}, {CommitIDs: []int64{5}}, {CommitIDs: []int64{2, 7}}}

	s := Summarise(SummaryInput{Landings: landings, CommittedAt: committed, PRs: prs, Prompts: prompts, Now: evalNow, EvidenceAt: evalNow.Add(-2 * time.Hour)})
	if s.AICommits != 7 || s.LandedExact != 1 || s.LandedPatch != 1 || s.LandedSquash != 1 {
		t.Fatalf("counts = %+v", s)
	}
	if !s.AcceptedWorkRate.Known || s.AcceptedWorkRate.Num != 3 || s.AcceptedWorkRate.Den != 4 {
		t.Fatalf("accepted = %+v", s.AcceptedWorkRate)
	}
	if s.LandedShare.Num != 3 || s.LandedShare.Den != 7 {
		t.Fatalf("share = %+v", s.LandedShare)
	}
	// No provider: PR numbers stay unknown even though PR rows exist, and
	// time to merge falls back to the local approximation.
	if s.PRMergeRate.Known || s.OpenMergeable.Known || s.TimeToMerge.Source != SourceUserRefs || s.TimeToMerge.Samples != 2 {
		t.Fatalf("local-only provider metrics: %+v %+v %+v", s.PRMergeRate, s.OpenMergeable, s.TimeToMerge)
	}
	if s.FetchAge != AgeUnder24h || s.StaleCaveat != "" {
		t.Fatalf("freshness = %q %q", s.FetchAge, s.StaleCaveat)
	}
	f := s.Funnel
	if !f.Known || f.EditedPrompts != 4 || f.Committed != 3 || f.Pushed != 2 || f.InPR != 2 || f.Landed != 1 {
		t.Fatalf("funnel = %+v", f)
	}

	// With a provider: PR metrics are known, time to merge is the PR's.
	s = Summarise(SummaryInput{Landings: landings, PRs: prs, ProviderConnected: true, CountLikely: true, Now: evalNow})
	if !s.PRMergeRate.Known || s.PRMergeRate.Num != 2 || s.PRMergeRate.Den != 3 {
		t.Fatalf("pr merge rate = %+v", s.PRMergeRate)
	}
	if !s.OpenMergeable.Known || s.OpenMergeable.Value != 1 || s.BlockedBacklog[ReadyConflicts] != 1 {
		t.Fatalf("open mergeable = %+v backlog = %+v", s.OpenMergeable, s.BlockedBacklog)
	}
	if s.TimeToMerge.Source != SourceProvider || s.TimeToMerge.P50 != time.Hour || s.TimeToMerge.P75 != 3*time.Hour {
		t.Fatalf("time to merge = %+v", s.TimeToMerge)
	}
	// L5 is reserved: count_likely does NOT put likely_landed on the
	// landed side, anywhere.
	if s.AcceptedWorkRate.Num != 3 || s.AcceptedWorkRate.Den != 4 || s.LandedShare.Num != 3 {
		t.Fatalf("count_likely moved likely_landed: accepted = %+v share = %+v", s.AcceptedWorkRate, s.LandedShare)
	}
	if s.OpenUnknown != 0 || len(s.BlockedBacklog) != 1 {
		t.Fatalf("open buckets: unknown = %d backlog = %+v", s.OpenUnknown, s.BlockedBacklog)
	}
	// An open PR with unknown readiness is neither mergeable nor blocked.
	s = Summarise(SummaryInput{PRs: []PullRequest{{State: PROpen, Readiness: ReadyUnknown}, {State: PROpen}}, ProviderConnected: true, Now: evalNow})
	if s.OpenMergeable.Value != 0 || len(s.BlockedBacklog) != 0 || s.OpenUnknown != 2 {
		t.Fatalf("unknown readiness: mergeable = %+v backlog = %+v unknown = %d", s.OpenMergeable, s.BlockedBacklog, s.OpenUnknown)
	}
}

func TestPercentiles(t *testing.T) {
	t.Parallel()
	ds := []time.Duration{5, 1, 4, 2, 3}
	p50, p75 := Percentiles(ds)
	if p50 != 3 || p75 != 4 {
		t.Fatalf("Percentiles = %v, %v", p50, p75)
	}
	if a, b := Percentiles(nil); a != 0 || b != 0 {
		t.Fatal("empty percentiles not zero")
	}
}
