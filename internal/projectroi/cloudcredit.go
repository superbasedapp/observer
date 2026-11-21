package projectroi

import (
	"sort"
	"strings"
	"time"
)

// cloudcredit.go credits commits a CLOUD coding agent produced to that
// cloud session (cloud-agents arc lane CA-C5; plan section 8 and the Wave C
// entry "Delivery attribution of cloud PRs";
// docs/projects-page.md "Cloud-agent credit").
//
// A cloud session (execution_location = vendor_cloud) leaves no local
// file_changes rows, so Link can never carry its work: before this file its
// commits read "none (human)" (rule O3) or, authored by the vendor's bot,
// "another author" (rule O2b). What a cloud session DOES leave is a pointer
// the vendor returned: a pull request (Copilot pullRequestUrl, Devin
// pull_requests[].pr_url) or a branch (a Cursor run's git.branches). This
// file turns those pointers into commit credit in two ORDERED tables, both
// walked top-down, first match decides:
//
// Claim resolution (cloudClaimRules), per claim: which PR(s) the claim
// names.
//
//	R1 stated_pr            - the vendor stated the PR number (and its
//	                          repository): that PR.
//	R2 branch_head_ref      - a branch claim whose branch is the head ref of
//	                          a provider PR (GitHub connection) on the same
//	                          repository, opened no earlier than the session
//	                          started: every such PR.
//	R3 branch_merge_subject - a branch claim on one of THIS project's
//	                          repositories whose branch a local merge commit's
//	                          grounded subject names ("Merge pull request #N
//	                          from owner/<branch>"), committed after the
//	                          session started: that PR N.
//	R4 unresolved           - a branch no PR evidence names yet: no credit.
//
// Commit credit (cloudCreditRules), per commit. The first three rows are
// gates that keep the ownership answer as it is:
//
//	K1 merge          - a merge commit never carries attribution (R4.4).
//	K2 unreachable    - a commit that fell out of HEAD carries nothing (R2).
//	K3 local_owner    - a local AI session already owns the commit: the
//	                    measured local answer stands.
//	C1 cloud_pr_commit  - the commit's sha is in the provider commit list of
//	                      a PR a claim resolved to, on one of this project's
//	                      repositories (exact).
//	C2 cloud_pr_landing - the commit IS the merge commit sha of such a PR
//	                      (a squash or rebase landing on the default branch).
//	C3 cloud_pr_subject - local-only mode: a non-merge commit whose grounded
//	                      squash subject (" (#N)") names such a PR's number,
//	                      committed after the claiming session started, on a
//	                      project whose remotes name exactly ONE repository
//	                      (a PR number means nothing across repositories).
//
// When a row matches, every claiming session that matches the SAME row is a
// contributor (a parent and a child Devin session may share one PR). They
// are ranked by cloudRanks (earliest session start, then session id, a total
// order) and share the commit equally (ShareBasisCloudClaim). The owner's
// Reason is the credit row's id, so a reader always sees WHY a cloud session
// was credited. A commit no row credits keeps its Ownership answer.
//
// Honesty: this is FILE-level reach through the vendor's own PR or branch
// pointer, never "line survival". A credited contributor's Files is the
// commit's file count and its CodeLines stay 0: Observer measured no AI line
// of a cloud session, so it states none (the UI says "not measured", never a
// number). Credit is never inferred from a branch-name prefix ("cursor/",
// "copilot/"), an author name or a time window alone.

// Cloud credit reasons (CommitOwnership.Reason of a cloud-credited commit).
const (
	OwnerCloudPRCommit  = "cloud_pr_commit"
	OwnerCloudPRLanding = "cloud_pr_landing"
	OwnerCloudPRSubject = "cloud_pr_subject"
)

// ShareBasisCloudClaim is the share basis of a cloud-credited commit: every
// claiming session shares it equally, because no line of a cloud session
// was measured.
const ShareBasisCloudClaim = "cloud_claim"

// Claim resolution rule ids (CloudClaimResolution.Rule).
const (
	ClaimStatedPR           = "stated_pr"
	ClaimBranchHeadRef      = "branch_head_ref"
	ClaimBranchMergeSubject = "branch_merge_subject"
	ClaimUnresolved         = "unresolved"
)

// Credit gate ids (the K rows; not reasons on the wire: a gated commit keeps
// its Ownership reason).
const (
	creditGateMerge       = "merge"
	creditGateUnreachable = "unreachable"
	creditGateLocalOwner  = "local_owner"
)

// CloudClaim is one pointer a cloud session's vendor returned: a pull
// request or a branch on a repository.
type CloudClaim struct {
	SessionID string
	Connector string
	// Remote is the repository as "host/owner/repo" (compared
	// case-insensitively).
	Remote string
	// PRNumber is the stated PR number (0 = none stated); Branch the
	// stated branch ("" = none). A claim carries one or the other or both.
	PRNumber int64
	Branch   string
	// SessionStart is when the claiming session started; zero when unknown
	// (rows that need it then do not match).
	SessionStart time.Time
}

// CloudPR is one provider PR as cloud credit needs it (from the delivery
// store's pull_requests rows).
type CloudPR struct {
	Remote         string
	Number         int64
	HeadRef        string
	MergeCommitSHA string
	CreatedAt      time.Time
	CommitSHAs     []string
}

// CloudCommit is one project commit's facts beyond Commit: the subject
// templates already parsed at the store boundary (delivery.SquashSubjectPR
// and delivery.MergeSubjectHead), so this package reads no subject text.
type CloudCommit struct {
	ID          int64
	SHA         string
	CommittedAt time.Time
	IsMerge     bool
	Reachable   bool
	Files       int
	// SquashPR is the PR number a squash subject names (0 = none).
	SquashPR int64
	// MergePR / MergeHead are the PR number and head branch a merge-commit
	// subject names (0 / "" = none).
	MergePR   int64
	MergeHead string
}

// CloudCreditInput is everything one cloud-credit fold of one project reads.
type CloudCreditInput struct {
	// ProjectRemotes are the project's repositories ("host/owner/repo").
	ProjectRemotes []string
	Claims         []CloudClaim
	PRs            []CloudPR
	Commits        []CloudCommit
}

// CloudClaimResolution is one claim's resolution.
type CloudClaimResolution struct {
	Claim CloudClaim
	// Rule is the claim rule id that decided (ClaimStatedPR, ...).
	Rule string
	// PRs are the PR numbers the claim names, ascending; empty when Rule is
	// ClaimUnresolved.
	PRs []int64
}

// remoteKey is the one comparison key of a repository.
func remoteKey(r string) string { return strings.ToLower(strings.TrimSpace(r)) }

// cloudIndex holds one fold's indexes.
type cloudIndex struct {
	in       CloudCreditInput
	project  map[string]bool
	prs      map[string]map[int64]*CloudPR // remote -> number -> PR
	prBySHA  map[string][]*CloudPR
	prByLand map[string][]*CloudPR
}

func newCloudIndex(in CloudCreditInput) *cloudIndex {
	x := &cloudIndex{
		in: in, project: map[string]bool{}, prs: map[string]map[int64]*CloudPR{},
		prBySHA: map[string][]*CloudPR{}, prByLand: map[string][]*CloudPR{},
	}
	for _, r := range in.ProjectRemotes {
		if k := remoteKey(r); k != "" {
			x.project[k] = true
		}
	}
	for i := range in.PRs {
		p := &in.PRs[i]
		k := remoteKey(p.Remote)
		if k == "" || p.Number <= 0 {
			continue
		}
		if x.prs[k] == nil {
			x.prs[k] = map[int64]*CloudPR{}
		}
		x.prs[k][p.Number] = p
		for _, sha := range p.CommitSHAs {
			x.prBySHA[sha] = append(x.prBySHA[sha], p)
		}
		if p.MergeCommitSHA != "" {
			x.prByLand[p.MergeCommitSHA] = append(x.prByLand[p.MergeCommitSHA], p)
		}
	}
	return x
}

// cloudClaimRule is one claim-resolution row: it returns the PR numbers it
// names and whether it matched.
type cloudClaimRule struct {
	id      string
	resolve func(x *cloudIndex, c CloudClaim) ([]int64, bool)
}

// cloudClaimRules is the ordered claim table (R1-R4). See the file comment.
var cloudClaimRules = []cloudClaimRule{
	{ClaimStatedPR, func(_ *cloudIndex, c CloudClaim) ([]int64, bool) {
		if c.PRNumber <= 0 || remoteKey(c.Remote) == "" {
			return nil, false
		}
		return []int64{c.PRNumber}, true
	}},
	{ClaimBranchHeadRef, func(x *cloudIndex, c CloudClaim) ([]int64, bool) {
		if c.Branch == "" || c.SessionStart.IsZero() {
			return nil, false
		}
		var out []int64
		for n, p := range x.prs[remoteKey(c.Remote)] {
			if p.HeadRef == c.Branch && !p.CreatedAt.IsZero() && !p.CreatedAt.Before(c.SessionStart) {
				out = append(out, n)
			}
		}
		return out, len(out) > 0
	}},
	{ClaimBranchMergeSubject, func(x *cloudIndex, c CloudClaim) ([]int64, bool) {
		if c.Branch == "" || c.SessionStart.IsZero() || !x.project[remoteKey(c.Remote)] {
			return nil, false
		}
		seen := map[int64]bool{}
		var out []int64
		for _, cm := range x.in.Commits {
			if cm.MergePR > 0 && cm.MergeHead == c.Branch && cm.CommittedAt.After(c.SessionStart) && !seen[cm.MergePR] {
				seen[cm.MergePR] = true
				out = append(out, cm.MergePR)
			}
		}
		return out, len(out) > 0
	}},
	{ClaimUnresolved, func(_ *cloudIndex, _ CloudClaim) ([]int64, bool) { return nil, true }},
}

// ResolveCloudClaims walks the claim table for every claim, in input order.
func ResolveCloudClaims(in CloudCreditInput) []CloudClaimResolution {
	return newCloudIndex(in).resolveAll()
}

func (x *cloudIndex) resolveAll() []CloudClaimResolution {
	out := make([]CloudClaimResolution, 0, len(x.in.Claims))
	for _, c := range x.in.Claims {
		for _, r := range cloudClaimRules {
			prs, ok := r.resolve(x, c)
			if !ok {
				continue
			}
			sort.Slice(prs, func(i, j int) bool { return prs[i] < prs[j] })
			out = append(out, CloudClaimResolution{Claim: c, Rule: r.id, PRs: prs})
			break
		}
	}
	return out
}

// cloudCreditRule is one commit-credit row. A gate row (gate=true) keeps the
// commit's Ownership answer when it matches; a credit row returns the
// claiming sessions that match it.
type cloudCreditRule struct {
	id    string
	gate  bool
	gated func(c CloudCommit, base CommitOwnership) bool
	match func(x *cloudIndex, c CloudCommit, r CloudClaimResolution) bool
}

// cloudCreditRules is the ordered commit table (K1-K3, C1-C3). See the file
// comment.
var cloudCreditRules = []cloudCreditRule{
	{id: creditGateMerge, gate: true, gated: func(c CloudCommit, _ CommitOwnership) bool { return c.IsMerge }},
	{id: creditGateUnreachable, gate: true, gated: func(c CloudCommit, _ CommitOwnership) bool { return !c.Reachable }},
	{id: creditGateLocalOwner, gate: true, gated: func(_ CloudCommit, b CommitOwnership) bool { return b.OwnerSessionID != "" }},
	{id: OwnerCloudPRCommit, match: func(x *cloudIndex, c CloudCommit, r CloudClaimResolution) bool {
		return x.claimHasPR(r, x.prBySHA[c.SHA])
	}},
	{id: OwnerCloudPRLanding, match: func(x *cloudIndex, c CloudCommit, r CloudClaimResolution) bool {
		return x.claimHasPR(r, x.prByLand[c.SHA])
	}},
	{id: OwnerCloudPRSubject, match: func(x *cloudIndex, c CloudCommit, r CloudClaimResolution) bool {
		if c.SquashPR <= 0 || len(x.project) != 1 || !x.project[remoteKey(r.Claim.Remote)] {
			return false
		}
		if r.Claim.SessionStart.IsZero() || !c.CommittedAt.After(r.Claim.SessionStart) {
			return false
		}
		for _, n := range r.PRs {
			if n == c.SquashPR {
				return true
			}
		}
		return false
	}},
}

// claimHasPR reports whether one of prs is a PR the resolution names, on the
// claim's repository, and that repository is one of this project's.
func (x *cloudIndex) claimHasPR(r CloudClaimResolution, prs []*CloudPR) bool {
	k := remoteKey(r.Claim.Remote)
	if !x.project[k] {
		return false
	}
	for _, p := range prs {
		if remoteKey(p.Remote) != k {
			continue
		}
		for _, n := range r.PRs {
			if n == p.Number {
				return true
			}
		}
	}
	return false
}

// cloudRank is one contributor ranking row (the cmp convention of
// ownershipRanks).
type cloudRank struct {
	id  string
	cmp func(a, b CloudClaim) int
}

// cloudRanks orders a commit's claiming sessions: earliest session start
// (an unknown start ranks last), then session id (a total order).
var cloudRanks = []cloudRank{
	{"earliest_session", func(a, b CloudClaim) int {
		switch {
		case a.SessionStart.Equal(b.SessionStart):
			return 0
		case a.SessionStart.IsZero():
			return 1
		case b.SessionStart.IsZero():
			return -1
		case a.SessionStart.Before(b.SessionStart):
			return -1
		}
		return 1
	}},
	{"session_id", func(a, b CloudClaim) int { return strings.Compare(a.SessionID, b.SessionID) }},
}

// CreditCloud overlays cloud credit on an Ownership answer: for every commit
// in in.Commits it walks cloudCreditRules and, when a credit row matches,
// replaces that commit's ownership with the claiming sessions. own is not
// mutated; the returned map holds every key of own. With no claims the input
// map is returned as is (byte-identical behaviour for a node with no cloud
// connector).
func CreditCloud(own map[int64]CommitOwnership, in CloudCreditInput) map[int64]CommitOwnership {
	if len(in.Claims) == 0 || len(in.Commits) == 0 {
		return own
	}
	x := newCloudIndex(in)
	res := x.resolveAll()
	out := make(map[int64]CommitOwnership, len(own))
	for k, v := range own {
		out[k] = v
	}
	for _, c := range in.Commits {
		base, ok := own[c.ID]
		if !ok {
			base = CommitOwnership{CommitID: c.ID, SHA: c.SHA, Reason: OwnerNoneNoAIEdits}
		}
		if o, credited := x.credit(c, base, res); credited {
			out[c.ID] = o
		}
	}
	return out
}

// credit walks the commit table for one commit.
func (x *cloudIndex) credit(c CloudCommit, base CommitOwnership, res []CloudClaimResolution) (CommitOwnership, bool) {
	for _, rule := range cloudCreditRules {
		if rule.gate {
			if rule.gated(c, base) {
				return base, false
			}
			continue
		}
		bySession := map[string]CloudClaim{}
		for _, r := range res {
			if len(r.PRs) == 0 || !rule.match(x, c, r) {
				continue
			}
			prev, seen := bySession[r.Claim.SessionID]
			if !seen || rankClaims(r.Claim, prev) < 0 {
				bySession[r.Claim.SessionID] = r.Claim
			}
		}
		if len(bySession) == 0 {
			continue
		}
		claims := make([]CloudClaim, 0, len(bySession))
		for _, cl := range bySession {
			claims = append(claims, cl)
		}
		sort.SliceStable(claims, func(i, j int) bool { return rankClaims(claims[i], claims[j]) < 0 })
		share := 1 / float64(len(claims))
		o := CommitOwnership{
			CommitID: c.ID, SHA: c.SHA, OwnerSessionID: claims[0].SessionID,
			Reason: rule.id, ShareBasis: ShareBasisCloudClaim,
		}
		for _, cl := range claims {
			o.Contributors = append(o.Contributors, CommitContributor{
				SessionID: cl.SessionID, Files: c.Files, Share: share,
			})
		}
		return o, true
	}
	return base, false
}

// rankClaims compares two claims through cloudRanks.
func rankClaims(a, b CloudClaim) int {
	for _, r := range cloudRanks {
		if d := r.cmp(a, b); d != 0 {
			return d
		}
	}
	return 0
}

// IsCloudCredit reports whether an ownership reason is a cloud credit row.
func IsCloudCredit(reason string) bool {
	switch reason {
	case OwnerCloudPRCommit, OwnerCloudPRLanding, OwnerCloudPRSubject:
		return true
	}
	return false
}
