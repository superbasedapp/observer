package projectroi

import (
	"reflect"
	"testing"
	"time"
)

var (
	ccT0      = time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	ccRemote  = "github.com/acme/app"
	ccOther   = "github.com/acme/other"
	ccSHA1    = "1111111111111111111111111111111111111111"
	ccSHA2    = "2222222222222222222222222222222222222222"
	ccSHALand = "3333333333333333333333333333333333333333"
)

// TestCloudClaimRules is one case per claim-resolution row (R1-R4), plus
// the near misses that must fall through to a later row.
func TestCloudClaimRules(t *testing.T) {
	prs := []CloudPR{
		{Remote: ccRemote, Number: 7, HeadRef: "cursor/fix-a", CreatedAt: ccT0.Add(time.Hour)},
		{Remote: ccRemote, Number: 9, HeadRef: "cursor/fix-a", CreatedAt: ccT0.Add(-time.Hour)}, // before the session
		{Remote: ccOther, Number: 8, HeadRef: "cursor/fix-b", CreatedAt: ccT0.Add(time.Hour)},
	}
	commits := []CloudCommit{
		{ID: 1, SHA: ccSHA1, CommittedAt: ccT0.Add(2 * time.Hour), IsMerge: true, Reachable: true, MergePR: 12, MergeHead: "cursor/fix-c"},
		{ID: 2, SHA: ccSHA2, CommittedAt: ccT0.Add(-2 * time.Hour), IsMerge: true, Reachable: true, MergePR: 13, MergeHead: "cursor/fix-d"},
	}
	cases := []struct {
		name  string
		claim CloudClaim
		rule  string
		prs   []int64
	}{
		{"R1 stated PR", CloudClaim{SessionID: "s", Remote: ccRemote, PRNumber: 5, SessionStart: ccT0}, ClaimStatedPR, []int64{5}},
		{"R1 needs a repository", CloudClaim{SessionID: "s", PRNumber: 5, SessionStart: ccT0}, ClaimUnresolved, nil},
		{"R2 branch is a provider PR head ref", CloudClaim{SessionID: "s", Remote: ccRemote, Branch: "cursor/fix-a", SessionStart: ccT0}, ClaimBranchHeadRef, []int64{7}},
		{"R2 other repository's head ref does not match", CloudClaim{SessionID: "s", Remote: ccRemote, Branch: "cursor/fix-b", SessionStart: ccT0}, ClaimUnresolved, nil},
		{"R2 needs a session start", CloudClaim{SessionID: "s", Remote: ccRemote, Branch: "cursor/fix-a"}, ClaimUnresolved, nil},
		{"R3 merge subject names the branch", CloudClaim{SessionID: "s", Remote: ccRemote, Branch: "cursor/fix-c", SessionStart: ccT0}, ClaimBranchMergeSubject, []int64{12}},
		{"R3 merge before the session does not match", CloudClaim{SessionID: "s", Remote: ccRemote, Branch: "cursor/fix-d", SessionStart: ccT0}, ClaimUnresolved, nil},
		{"R3 needs this project's repository", CloudClaim{SessionID: "s", Remote: ccOther, Branch: "cursor/fix-c", SessionStart: ccT0}, ClaimUnresolved, nil},
		{"R4 a branch no PR names", CloudClaim{SessionID: "s", Remote: ccRemote, Branch: "cursor/zzz", SessionStart: ccT0}, ClaimUnresolved, nil},
		{"remote compares case-insensitively", CloudClaim{SessionID: "s", Remote: "GitHub.com/ACME/app", Branch: "cursor/fix-a", SessionStart: ccT0}, ClaimBranchHeadRef, []int64{7}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ResolveCloudClaims(CloudCreditInput{
				ProjectRemotes: []string{ccRemote}, Claims: []CloudClaim{tc.claim}, PRs: prs, Commits: commits,
			})
			if len(got) != 1 {
				t.Fatalf("got %d resolutions", len(got))
			}
			if got[0].Rule != tc.rule || !reflect.DeepEqual(got[0].PRs, tc.prs) {
				t.Fatalf("rule %q prs %v, want %q %v", got[0].Rule, got[0].PRs, tc.rule, tc.prs)
			}
		})
	}
}

// TestCloudCreditRules is one case per commit-credit row (K1-K3, C1-C3) and
// the fall-through case.
func TestCloudCreditRules(t *testing.T) {
	claim := CloudClaim{SessionID: "cloud-1", Connector: "copilot-agent", Remote: ccRemote, PRNumber: 7, SessionStart: ccT0}
	pr := CloudPR{Remote: ccRemote, Number: 7, MergeCommitSHA: ccSHALand, CommitSHAs: []string{ccSHA1}, CreatedAt: ccT0}
	none := CommitOwnership{Reason: OwnerNoneNoAIEdits}
	foreign := CommitOwnership{Reason: OwnerNoneForeignAuthor}
	local := CommitOwnership{OwnerSessionID: "local-1", Reason: OwnerSoleContributor}
	after := ccT0.Add(time.Hour)
	cases := []struct {
		name    string
		remotes []string
		commit  CloudCommit
		base    CommitOwnership
		prs     []CloudPR
		reason  string // "" = not credited
	}{
		{"K1 merge never carries", []string{ccRemote}, CloudCommit{ID: 1, SHA: ccSHA1, IsMerge: true, Reachable: true, CommittedAt: after}, none, []CloudPR{pr}, ""},
		{"K2 unreachable carries nothing", []string{ccRemote}, CloudCommit{ID: 1, SHA: ccSHA1, Reachable: false, CommittedAt: after}, none, []CloudPR{pr}, ""},
		{"K3 a local owner stands", []string{ccRemote}, CloudCommit{ID: 1, SHA: ccSHA1, Reachable: true, CommittedAt: after}, local, []CloudPR{pr}, ""},
		{"C1 sha in the claimed PR", []string{ccRemote}, CloudCommit{ID: 1, SHA: ccSHA1, Reachable: true, CommittedAt: after, Files: 3}, foreign, []CloudPR{pr}, OwnerCloudPRCommit},
		{"C1 not on this project's repository", []string{ccOther}, CloudCommit{ID: 1, SHA: ccSHA1, Reachable: true, CommittedAt: after}, foreign, []CloudPR{pr}, ""},
		{"C2 the claimed PR's landing commit", []string{ccRemote}, CloudCommit{ID: 2, SHA: ccSHALand, Reachable: true, CommittedAt: after}, none, []CloudPR{pr}, OwnerCloudPRLanding},
		{"C3 squash subject names the claimed PR", []string{ccRemote}, CloudCommit{ID: 3, SHA: ccSHA2, Reachable: true, CommittedAt: after, SquashPR: 7}, none, nil, OwnerCloudPRSubject},
		{"C3 not before the session started", []string{ccRemote}, CloudCommit{ID: 3, SHA: ccSHA2, Reachable: true, CommittedAt: ccT0.Add(-time.Hour), SquashPR: 7}, none, nil, ""},
		{"C3 not with two repositories", []string{ccRemote, ccOther}, CloudCommit{ID: 3, SHA: ccSHA2, Reachable: true, CommittedAt: after, SquashPR: 7}, none, nil, ""},
		{"C3 another PR number", []string{ccRemote}, CloudCommit{ID: 3, SHA: ccSHA2, Reachable: true, CommittedAt: after, SquashPR: 8}, none, nil, ""},
		{"no row: keeps the ownership answer", []string{ccRemote}, CloudCommit{ID: 4, SHA: ccSHA2, Reachable: true, CommittedAt: after}, none, []CloudPR{pr}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := tc.base
			base.CommitID, base.SHA = tc.commit.ID, tc.commit.SHA
			own := map[int64]CommitOwnership{tc.commit.ID: base}
			got := CreditCloud(own, CloudCreditInput{
				ProjectRemotes: tc.remotes, Claims: []CloudClaim{claim}, PRs: tc.prs, Commits: []CloudCommit{tc.commit},
			})[tc.commit.ID]
			if tc.reason == "" {
				if !reflect.DeepEqual(got, base) {
					t.Fatalf("credited %+v, want the base answer %+v", got, base)
				}
				return
			}
			if got.Reason != tc.reason || got.OwnerSessionID != "cloud-1" || got.ShareBasis != ShareBasisCloudClaim {
				t.Fatalf("got %+v, want reason %q owner cloud-1", got, tc.reason)
			}
			if len(got.Contributors) != 1 || got.Contributors[0].Share != 1 || got.Contributors[0].Files != tc.commit.Files || got.Contributors[0].CodeLines != 0 {
				t.Fatalf("contributors = %+v", got.Contributors)
			}
			if !IsCloudCredit(got.Reason) {
				t.Fatalf("IsCloudCredit(%q) = false", got.Reason)
			}
		})
	}
}

// TestCloudRanks pins the contributor ranking rows: earliest session start
// first (unknown last), then session id; shares are equal.
func TestCloudRanks(t *testing.T) {
	commit := CloudCommit{ID: 1, SHA: ccSHA1, Reachable: true, CommittedAt: ccT0.Add(time.Hour), Files: 2}
	pr := CloudPR{Remote: ccRemote, Number: 7, CommitSHAs: []string{ccSHA1}}
	cases := []struct {
		name   string
		claims []CloudClaim
		want   []string
	}{
		{"earliest session first", []CloudClaim{
			{SessionID: "b", Remote: ccRemote, PRNumber: 7, SessionStart: ccT0},
			{SessionID: "a", Remote: ccRemote, PRNumber: 7, SessionStart: ccT0.Add(time.Minute)},
		}, []string{"b", "a"}},
		{"unknown start ranks last", []CloudClaim{
			{SessionID: "a", Remote: ccRemote, PRNumber: 7},
			{SessionID: "b", Remote: ccRemote, PRNumber: 7, SessionStart: ccT0},
		}, []string{"b", "a"}},
		{"tie broken by session id", []CloudClaim{
			{SessionID: "b", Remote: ccRemote, PRNumber: 7, SessionStart: ccT0},
			{SessionID: "a", Remote: ccRemote, PRNumber: 7, SessionStart: ccT0},
		}, []string{"a", "b"}},
		{"one session with two claims counts once", []CloudClaim{
			{SessionID: "a", Remote: ccRemote, PRNumber: 7, SessionStart: ccT0},
			{SessionID: "a", Remote: ccRemote, Branch: "x", PRNumber: 7, SessionStart: ccT0},
		}, []string{"a"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := CreditCloud(map[int64]CommitOwnership{}, CloudCreditInput{
				ProjectRemotes: []string{ccRemote}, Claims: tc.claims, PRs: []CloudPR{pr}, Commits: []CloudCommit{commit},
			})[1]
			var ids []string
			for _, c := range got.Contributors {
				ids = append(ids, c.SessionID)
				if want := 1 / float64(len(tc.want)); c.Share != want {
					t.Fatalf("share %v, want %v", c.Share, want)
				}
			}
			if !reflect.DeepEqual(ids, tc.want) || got.OwnerSessionID != tc.want[0] {
				t.Fatalf("contributors %v owner %q, want %v", ids, got.OwnerSessionID, tc.want)
			}
		})
	}
}

// TestCreditCloudNoClaimsIsIdentity: a node with no cloud connector gets
// the exact map it passed in.
func TestCreditCloudNoClaimsIsIdentity(t *testing.T) {
	own := map[int64]CommitOwnership{1: {CommitID: 1, Reason: OwnerNoneNoAIEdits}}
	got := CreditCloud(own, CloudCreditInput{Commits: []CloudCommit{{ID: 1, Reachable: true}}})
	if !reflect.DeepEqual(got, own) {
		t.Fatalf("got %+v", got)
	}
	// The input map is never mutated by a credit.
	in := map[int64]CommitOwnership{1: {CommitID: 1, SHA: ccSHA1, Reason: OwnerNoneNoAIEdits}}
	_ = CreditCloud(in, CloudCreditInput{
		ProjectRemotes: []string{ccRemote},
		Claims:         []CloudClaim{{SessionID: "c", Remote: ccRemote, PRNumber: 7, SessionStart: ccT0}},
		PRs:            []CloudPR{{Remote: ccRemote, Number: 7, CommitSHAs: []string{ccSHA1}}},
		Commits:        []CloudCommit{{ID: 1, SHA: ccSHA1, Reachable: true, CommittedAt: ccT0.Add(time.Hour)}},
	})
	if in[1].Reason != OwnerNoneNoAIEdits {
		t.Fatalf("input mutated: %+v", in[1])
	}
}
