package delivery

import (
	"testing"
	"time"
)

var evalNow = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

// aiCommit is an AI-touched, reachable commit with a computed fingerprint,
// committed a day ago.
func aiCommit(id int64, sha string) Commit {
	return Commit{
		ID: id, ProjectID: 1, SHA: sha, CommittedAt: evalNow.Add(-24 * time.Hour),
		Reachable: true, PatchFP: "fp-" + sha, PatchFPState: FPOK, AIContributor: true,
		SessionIDs: []string{"s1"},
	}
}

func evalOne(t *testing.T, in EvalInput) (Landing, bool) {
	t.Helper()
	if in.Now.IsZero() {
		in.Now = evalNow
	}
	if in.Source == "" {
		in.Source = SourceUserRefs
	}
	out := Evaluate(in)
	if len(out) > 1 {
		t.Fatalf("got %d landings, want at most 1", len(out))
	}
	if len(out) == 0 {
		return Landing{}, false
	}
	return out[0], true
}

func mergedPR(id, number int64, mergeSHA string, method MergeMethod, shas ...string) PRWithCommits {
	p := PRWithCommits{PR: PullRequest{
		ID: id, Number: number, State: PRMerged, MergeCommitSHA: mergeSHA, MergeMethod: method,
		BaseRef: "main", CreatedAt: evalNow.Add(-48 * time.Hour), MergedAt: evalNow.Add(-2 * time.Hour),
	}}
	for i, s := range shas {
		p.Commits = append(p.Commits, PRCommit{SHA: s, Position: i})
	}
	return p
}

// TestEvaluateRules is one case per row of evalRules, in table order.
func TestEvaluateRules(t *testing.T) {
	t.Parallel()
	c := aiCommit(1, "aaa")
	old := c
	old.CommittedAt = evalNow.Add(-40 * 24 * time.Hour)

	type want struct {
		written bool
		rule    string
		status  LandingStatus
		kind    LandingKind
		conf    Confidence
		pr      int64
		reason  AbandonReason
	}
	cases := []struct {
		row  string
		in   EvalInput
		want want
	}{
		{"G1 merge", EvalInput{Commits: []Commit{{ID: 1, SHA: "m", IsMerge: true, AIContributor: true, PatchFPState: FPOK}}}, want{}},
		{"G1 foreign author", EvalInput{Commits: []Commit{{ID: 1, SHA: "f", ForeignAuthor: true, AIContributor: true, PatchFPState: FPOK}}}, want{}},
		{"G1 no AI contributor", EvalInput{Commits: []Commit{{ID: 1, SHA: "h", PatchFPState: FPOK}}}, want{}},
		{"G2 pending fingerprint", EvalInput{Commits: []Commit{{ID: 1, SHA: "p", AIContributor: true, PatchFPState: FPPending}}}, want{}},
		{"P1 merged PR lists sha", EvalInput{
			Commits: []Commit{c},
			PRs:     []PRWithCommits{mergedPR(7, 41, "mc", MergeSquash, "aaa")},
		}, want{true, "P1", StatusLanded, KindSquash, ConfExact, 41, ""}},
		{"L1 ancestor of default", EvalInput{
			Commits: []Commit{c},
			Default: DefaultEvidence{Known: true, Ancestor: map[string]bool{"aaa": true}},
		}, want{true, "L1", StatusLanded, KindExactSHA, ConfExact, 0, ""}},
		{"P2 merged PR holds our fingerprint", EvalInput{
			Commits: []Commit{c},
			PRs: []PRWithCommits{{
				PR:      PullRequest{ID: 8, Number: 42, State: PRMerged, MergeMethod: MergeRebase},
				Commits: []PRCommit{{SHA: "rebased", PatchFP: "fp-aaa"}},
			}},
		}, want{true, "P2", StatusLanded, KindRebase, ConfHigh, 42, ""}},
		{"L2 default commit has our fingerprint", EvalInput{
			Commits: []Commit{c},
			Default: DefaultEvidence{Known: true, Commits: []DefaultCommit{{SHA: "d1", Parents: 1, Subject: "x", PatchFP: "fp-aaa"}}},
		}, want{true, "L2", StatusLanded, KindPatchID, ConfHigh, 0, ""}},
		{"L3 squash of a branch range", EvalInput{
			Commits:    []Commit{c},
			Default:    DefaultEvidence{Known: true, Commits: []DefaultCommit{{SHA: "sq", Parents: 1, Subject: "Add parser (#43)", PatchFP: "range-fp"}}},
			BranchTips: []BranchTip{{TipSHA: "aaa", MemberSHAs: []string{"aaa", "bbb"}, RangeFP: "range-fp", RangeFPState: FPOK}},
		}, want{true, "L3", StatusLanded, KindSquash, ConfHigh, 43, ""}},
		{"M1 landing lost", EvalInput{
			Commits:  []Commit{c},
			Default:  DefaultEvidence{Known: true, Ancestor: map[string]bool{"gone": false}},
			Previous: map[int64]Landing{1: {CommitID: 1, Status: StatusLanded, Kind: KindPatchID, LandingSHA: "gone", RuleID: "L2", RuleVersion: RuleVersion}},
		}, want{true, "M1", StatusLandingLost, KindPatchID, "", 0, ""}},
		{"M2 landed stays landed", EvalInput{
			Commits:  []Commit{c},
			Previous: map[int64]Landing{1: {CommitID: 1, Status: StatusLanded, Kind: KindSquash, Confidence: ConfHigh, LandingSHA: "sq", RuleID: "L3", RuleVersion: RuleVersion}},
		}, want{true, "L3", StatusLanded, KindSquash, ConfHigh, 0, ""}},
		{"M3 landing lost stays lost", EvalInput{
			Commits:  []Commit{c},
			Previous: map[int64]Landing{1: {CommitID: 1, Status: StatusLandingLost, Kind: KindPatchID, RuleID: "M1", RuleVersion: RuleVersion}},
		}, want{true, "M1", StatusLandingLost, KindPatchID, "", 0, ""}},
		{"P3 open PR lists sha", EvalInput{
			Commits: []Commit{c},
			PRs:     []PRWithCommits{{PR: PullRequest{ID: 9, Number: 44, State: PROpen, Readiness: ReadyConflicts}, Commits: []PRCommit{{SHA: "aaa"}}}},
		}, want{true, "P3", StatusInPR, "", ConfExact, 44, ""}},
		{"P4 closed unmerged PR", EvalInput{
			Commits: []Commit{c},
			PRs:     []PRWithCommits{{PR: PullRequest{ID: 10, Number: 45, State: PRClosedUnmerged}, Commits: []PRCommit{{SHA: "aaa"}}}},
		}, want{true, "P4", StatusAbandoned, "", ConfExact, 45, AbandonPRClosed}},
		{"L4 squash with the same files", EvalInput{
			Commits: []Commit{c},
			Default: DefaultEvidence{Known: true, Commits: []DefaultCommit{{
				SHA: "sq2", Parents: 1, Subject: "Fix parser (#46)", PatchFP: "other", CommittedAt: evalNow, Files: []string{"b.go", "a.go"},
			}}},
			BranchTips: []BranchTip{{MemberSHAs: []string{"aaa"}, RangeFP: "range-fp", RangeFPState: FPOK, Files: []string{"a.go", "b.go"}}},
		}, want{true, "L4", StatusLanded, KindSquashFiles, ConfMedium, 46, ""}},
		{"L6 on a remote-tracking ref", EvalInput{
			Commits:         []Commit{c},
			RemoteReachable: map[string]bool{"aaa": true},
		}, want{true, "L6", StatusPushed, "", ConfExact, 0, ""}},
		{"L7 rewritten away, past the window", EvalInput{
			Commits: []Commit{func() Commit { x := old; x.Reachable = false; return x }()},
		}, want{true, "L7", StatusAbandoned, "", ConfMedium, 0, AbandonDropped}},
		{"L8 young: in flight", EvalInput{Commits: []Commit{c}}, want{true, "L8", StatusInFlight, "", "", 0, ""}},
		{"L8 old: local only", EvalInput{Commits: []Commit{old}}, want{true, "L8", StatusLocalOnly, "", "", 0, ""}},
	}
	rowsSeen := map[string]bool{}
	for _, tc := range cases {
		got, written := evalOne(t, tc.in)
		if written != tc.want.written {
			t.Errorf("%s: written = %v, want %v (%+v)", tc.row, written, tc.want.written, got)
			continue
		}
		rowsSeen[tc.row[:2]] = true
		if !written {
			continue
		}
		if got.RuleID != tc.want.rule || got.Status != tc.want.status || got.Kind != tc.want.kind ||
			got.Confidence != tc.want.conf || got.PRNumber != tc.want.pr || got.AbandonReason != tc.want.reason {
			t.Errorf("%s: got rule=%s status=%s kind=%s conf=%s pr=%d reason=%s", tc.row,
				got.RuleID, got.Status, got.Kind, got.Confidence, got.PRNumber, got.AbandonReason)
		}
		if got.CommitID != 1 || !got.EvaluatedAt.Equal(evalNow) || len(got.SessionIDs) != 1 {
			t.Errorf("%s: stamping wrong: %+v", tc.row, got)
		}
	}
	for _, r := range evalRules {
		if !rowsSeen[r.id] {
			t.Errorf("rule row %s has no test case", r.id)
		}
	}
}

// TestEvaluateOrdering pins the precedence the table encodes.
func TestEvaluateOrdering(t *testing.T) {
	t.Parallel()
	c := aiCommit(1, "aaa")

	// P1 beats L1: it also names the PR and the merge method.
	got, _ := evalOne(t, EvalInput{
		Commits: []Commit{c},
		PRs:     []PRWithCommits{mergedPR(7, 41, "mc", MergeCommit, "aaa")},
		Default: DefaultEvidence{Known: true, Ancestor: map[string]bool{"aaa": true}},
	})
	if got.RuleID != "P1" || got.Kind != KindMerge || got.Source != SourceProvider || got.LandedAtSource != LandedAtProvider {
		t.Fatalf("P1 vs L1: %+v", got)
	}

	// A PR merged into another base is not a landing; an open PR into the
	// default branch still reads in_pr.
	pr := mergedPR(7, 41, "mc", MergeCommit, "aaa")
	pr.PR.BaseRef = "release"
	got, _ = evalOne(t, EvalInput{Commits: []Commit{c}, PRs: []PRWithCommits{pr}, Default: DefaultEvidence{Branch: "main"}})
	if got.Status == StatusLanded {
		t.Fatalf("PR into another base landed: %+v", got)
	}

	// Landing is monotonic: a landed commit does not drop back to pushed.
	prev := Landing{
		CommitID: 1, Status: StatusLanded, Kind: KindExactSHA, RuleID: "L1", RuleVersion: RuleVersion,
		LandedAt: evalNow.Add(-time.Hour), LandedAtSource: LandedAtFirstSeen, FirstPushedAt: evalNow.Add(-5 * time.Hour),
	}
	got, _ = evalOne(t, EvalInput{Commits: []Commit{c}, RemoteReachable: map[string]bool{"aaa": true}, Previous: map[int64]Landing{1: prev}})
	if got.Status != StatusLanded || !got.LandedAt.Equal(prev.LandedAt) || !got.FirstPushedAt.Equal(prev.FirstPushedAt) {
		t.Fatalf("monotonic: %+v", got)
	}

	// A landed row under an older rule version is re-evaluated.
	prevOld := prev
	prevOld.RuleVersion = RuleVersion - 1
	got, _ = evalOne(t, EvalInput{Commits: []Commit{c}, RemoteReachable: map[string]bool{"aaa": true}, Previous: map[int64]Landing{1: prevOld}})
	if got.Status != StatusPushed || got.RuleVersion != RuleVersion {
		t.Fatalf("old rule version kept: %+v", got)
	}

	// A reopened PR (P4 abandoned last pass, open now) flips back to in_pr.
	abandoned := Landing{CommitID: 1, Status: StatusAbandoned, AbandonReason: AbandonPRClosed, RuleID: "P4", RuleVersion: RuleVersion}
	got, _ = evalOne(t, EvalInput{
		Commits:  []Commit{c},
		PRs:      []PRWithCommits{{PR: PullRequest{ID: 9, Number: 44, State: PROpen}, Commits: []PRCommit{{SHA: "aaa"}}}},
		Previous: map[int64]Landing{1: abandoned},
	})
	if got.Status != StatusInPR {
		t.Fatalf("reopened PR: %+v", got)
	}

	// L1 with the merge commit that brought the sha in: PR number and time.
	got, _ = evalOne(t, EvalInput{
		Commits: []Commit{c},
		Default: DefaultEvidence{Known: true, Ancestor: map[string]bool{"aaa": true}, LandedVia: map[string]DefaultCommit{
			"aaa": {SHA: "mc", Parents: 2, Subject: "Merge pull request #14706 from o/b", CommittedAt: evalNow.Add(-3 * time.Hour)},
		}},
	})
	if got.PRNumber != 14706 || got.LandedAtSource != LandedAtMergeCommit || !got.LandedAt.Equal(evalNow.Add(-3*time.Hour)) {
		t.Fatalf("L1 via merge commit: %+v", got)
	}

	// L1 with no merge commit known: first seen now.
	got, _ = evalOne(t, EvalInput{Commits: []Commit{c}, Default: DefaultEvidence{Known: true, Ancestor: map[string]bool{"aaa": true}}})
	if got.LandedAtSource != LandedAtFirstSeen || !got.LandedAt.Equal(evalNow) {
		t.Fatalf("L1 first seen: %+v", got)
	}

	// A too-large commit never matches by fingerprint.
	big := c
	big.PatchFPState = FPTooLarge
	got, _ = evalOne(t, EvalInput{Commits: []Commit{big}, Default: DefaultEvidence{Known: true, Commits: []DefaultCommit{{SHA: "d", PatchFP: "fp-aaa"}}}})
	if got.Status == StatusLanded {
		t.Fatalf("too_large landed by fingerprint: %+v", got)
	}

	// P4 yields to L4 when the closed PR's work landed as a squash anyway.
	got, _ = evalOne(t, EvalInput{
		Commits:    []Commit{c},
		PRs:        []PRWithCommits{{PR: PullRequest{ID: 10, Number: 45, State: PRClosedUnmerged}, Commits: []PRCommit{{SHA: "aaa"}}}},
		Default:    DefaultEvidence{Known: true, Commits: []DefaultCommit{{SHA: "sq", Subject: "Redo (#46)", CommittedAt: evalNow, Files: []string{"a.go"}}}},
		BranchTips: []BranchTip{{MemberSHAs: []string{"aaa"}, Files: []string{"a.go"}}},
	})
	if got.RuleID != "L4" {
		t.Fatalf("P4 vs L4: %+v", got)
	}
}

// TestEvaluateFixtureMergeCommit runs P1 over the Phase 0 merge-commit
// fixtures (cli/cli #14706): the branch commit lands as a merge, with the
// PR number, and the merge method inferred from the local merge commit
// when the provider did not name it.
func TestEvaluateFixtureMergeCommit(t *testing.T) {
	t.Parallel()
	var pr ghFixturePR
	readFixture(t, "pull_merged_mergecommit.json", &pr)
	var prCommits []struct {
		SHA string `json:"sha"`
	}
	readFixture(t, "pull_commits_merged.json", &prCommits)
	var mc struct {
		SHA     string `json:"sha"`
		Parents []struct {
			SHA string `json:"sha"`
		} `json:"parents"`
		Commit struct {
			Message string `json:"message"`
		} `json:"commit"`
	}
	readFixture(t, "commit_merge_commit.json", &mc)

	state, _, _, _ := MapGitHubPR(pr.input())
	p := PRWithCommits{PR: PullRequest{ID: 1, Number: pr.Number, State: state, MergeCommitSHA: mc.SHA, BaseRef: "trunk"}}
	for i, c := range prCommits {
		p.Commits = append(p.Commits, PRCommit{SHA: c.SHA, Position: i})
	}
	ours := aiCommit(5, prCommits[1].SHA)
	got, _ := evalOne(t, EvalInput{
		Commits: []Commit{ours},
		PRs:     []PRWithCommits{p},
		Default: DefaultEvidence{Known: true, Branch: "trunk", Commits: []DefaultCommit{{SHA: mc.SHA, Parents: len(mc.Parents), Subject: mc.Commit.Message}}},
	})
	if got.RuleID != "P1" || got.Kind != KindMerge || got.PRNumber != 14706 || got.LandingSHA != mc.SHA {
		t.Fatalf("fixture P1: %+v", got)
	}
}
