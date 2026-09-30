package projectroi

import (
	"sort"
	"time"
)

// ownership.go answers "which session owned this git commit?" (operator
// ask 2026-09-28). It is a PURE fold over a Linkage Link already produced
// - it adds no second matching rule. A commit's contributors are exactly
// the sessions whose (prompt, path) pairs Link says the commit CARRIED
// (ChainFile.CommitID == commit, not superseded); ownership is then an
// ORDERED, table-driven choice among them.
//
// THE RULE (docs/projects-page.md "Commit ownership"):
//
// Eligibility, walked top-down (ownershipGates), first match decides that
// the commit has NO owner:
//
//	O1 merge        - a merge commit never carries attribution (R4.4).
//	O2 unreachable  - a commit that fell out of HEAD carries nothing (R2).
//	O2b foreign_author - the commit's author is not the repository's local
//	                  git identity (a teammate's commit pulled into the
//	                  checkout; Commit.ForeignAuthor): owner = none, and
//	                  Link never lets it carry a local prompt's files. An
//	                  UNKNOWN local identity never matches this row, so the
//	                  rule then behaves exactly as before the author check.
//	O3 no_ai_edits  - no AI edit reached this commit: owner = none. This is
//	                  a human (or un-captured) commit and is NEVER guessed.
//
// Ranking, walked top-down (ownershipRanks), the first row that separates
// the top two contributors decides the owner and becomes the Reason:
//
//	O4 most_code_lines  - most AI code lines (added + modified, code files
//	                      only) the commit carried from that session.
//	O5 most_files       - most distinct files carried.
//	O6 earliest_prompt  - the session whose first carried prompt is earliest.
//	O7 session_id       - lexicographically smallest session id (a total
//	                      order, so the answer is deterministic).
//
// A single contributor is the owner with Reason "sole_contributor".
//
// Shares: every contributor carries a Share of the commit. The basis is
// CODE LINES when any contributor carried code lines, else FILES (a commit
// whose AI-touched files were docs/config only), so shares always sum to 1
// across a commit's contributors.
//
// Sidechain (sub-agent) edits are folded into their PARENT session by the
// loader before Link (R4.1), so a sub-agent's work makes its parent session
// the owner, never the child.

// Owner reasons. The first four mean "no owner"; the rest name the ranking
// row that decided the owner.
const (
	OwnerNoneMerge         = "merge"
	OwnerNoneUnreachable   = "unreachable"
	OwnerNoneForeignAuthor = "foreign_author"
	OwnerNoneNoAIEdits     = "no_ai_edits"

	OwnerSoleContributor = "sole_contributor"
	OwnerMostCodeLines   = "most_code_lines"
	OwnerMostFiles       = "most_files"
	OwnerEarliestPrompt  = "earliest_prompt"
	OwnerSessionID       = "session_id"
)

// Share bases.
const (
	ShareBasisCodeLines = "code_lines"
	ShareBasisFiles     = "files"
)

// CommitContributor is one session's contribution to one commit.
type CommitContributor struct {
	SessionID string
	// Files is the distinct paths this session's carried pairs cover.
	Files int
	// CodeLines / CommentLines are the carried pairs' AI code lines
	// (added + modified) and added comment lines, code files only.
	CodeLines    int
	CommentLines int
	// Prompts is how many distinct prompts of this session reached the
	// commit; FirstPromptAt the earliest of them.
	Prompts       int
	FirstPromptAt time.Time
	// PromptActionIDs are those prompts' action ids, ascending by time.
	PromptActionIDs []int64
	// Share is this session's share of the commit on ShareBasis; the
	// contributors of one commit sum to 1.
	Share float64
}

// CommitOwnership is one commit's ownership outcome.
type CommitOwnership struct {
	CommitID int64
	SHA      string
	// OwnerSessionID is the owning session, or "" when the commit has no
	// owner (Reason is then one of the OwnerNone* values).
	OwnerSessionID string
	Reason         string
	// ShareBasis is ShareBasisCodeLines or ShareBasisFiles; empty when
	// there are no contributors.
	ShareBasis string
	// Contributors are ranked by the ownership table; Contributors[0] is
	// the owner whenever OwnerSessionID is set.
	Contributors []CommitContributor
}

// ownershipGate is one eligibility row: when it matches, the commit has
// no owner and the row's reason is recorded.
type ownershipGate struct {
	reason  string
	matches func(c Commit, contributors int) bool
}

// ownershipGates is the ordered eligibility table (O1, O2, O2b, O3).
var ownershipGates = []ownershipGate{
	{OwnerNoneMerge, func(c Commit, _ int) bool { return c.IsMerge }},
	{OwnerNoneUnreachable, func(c Commit, _ int) bool { return !c.Reachable }},
	{OwnerNoneForeignAuthor, func(c Commit, _ int) bool { return c.ForeignAuthor }},
	{OwnerNoneNoAIEdits, func(_ Commit, n int) bool { return n == 0 }},
}

// ownershipRank is one ranking row: cmp returns <0 when a outranks b, >0
// when b outranks a, 0 when this row cannot separate them.
type ownershipRank struct {
	reason string
	cmp    func(a, b *CommitContributor) int
}

// ownershipRanks is the ordered ranking table (O4-O7). The last row is a
// total order, so ranking is always deterministic.
var ownershipRanks = []ownershipRank{
	{OwnerMostCodeLines, func(a, b *CommitContributor) int { return b.CodeLines - a.CodeLines }},
	{OwnerMostFiles, func(a, b *CommitContributor) int { return b.Files - a.Files }},
	{OwnerEarliestPrompt, func(a, b *CommitContributor) int {
		switch {
		case a.FirstPromptAt.Before(b.FirstPromptAt):
			return -1
		case b.FirstPromptAt.Before(a.FirstPromptAt):
			return 1
		}
		return 0
	}},
	{OwnerSessionID, func(a, b *CommitContributor) int {
		switch {
		case a.SessionID < b.SessionID:
			return -1
		case a.SessionID > b.SessionID:
			return 1
		}
		return 0
	}},
}

// rankContributors sorts in place by the ranking table and returns the
// reason of the row that separated the top two (the owner's reason).
func rankContributors(cs []CommitContributor) string {
	sort.SliceStable(cs, func(i, j int) bool {
		for _, r := range ownershipRanks {
			if d := r.cmp(&cs[i], &cs[j]); d != 0 {
				return d < 0
			}
		}
		return false
	})
	if len(cs) == 1 {
		return OwnerSoleContributor
	}
	for _, r := range ownershipRanks {
		if r.cmp(&cs[0], &cs[1]) != 0 {
			return r.reason
		}
	}
	return OwnerSessionID // unreachable: session ids are distinct
}

// Ownership folds a Linkage into one CommitOwnership per input commit
// (keyed by commit id). commits is the same slice Link ran over; a commit
// Link never saw has no contributors and is owner=none.
func Ownership(linkage Linkage, commits []Commit) map[int64]CommitOwnership {
	type sessAgg struct {
		c       CommitContributor
		paths   map[string]bool
		prompts map[int64]time.Time
	}
	perCommit := make(map[int64]map[string]*sessAgg)
	for _, chain := range linkage.Chains {
		p := chain.Prompt
		for _, f := range chain.Files {
			if f.Superseded || f.CommitID == 0 {
				continue
			}
			bySess := perCommit[f.CommitID]
			if bySess == nil {
				bySess = make(map[string]*sessAgg)
				perCommit[f.CommitID] = bySess
			}
			a := bySess[p.SessionID]
			if a == nil {
				a = &sessAgg{c: CommitContributor{SessionID: p.SessionID}, paths: map[string]bool{}, prompts: map[int64]time.Time{}}
				bySess[p.SessionID] = a
			}
			a.paths[f.PathHash] = true
			a.c.CodeLines += f.Added + f.Modified
			a.c.CommentLines += f.Comment
			a.prompts[p.ActionID] = p.At
		}
	}

	out := make(map[int64]CommitOwnership, len(commits))
	for _, c := range commits {
		own := CommitOwnership{CommitID: c.ID, SHA: c.SHA}
		var cs []CommitContributor
		// A merge/unreachable/foreign-author commit is never carried by
		// Link, but the gates are still walked first so the recorded
		// reason names WHY.
		if !c.IsMerge && c.Reachable && !c.ForeignAuthor {
			for _, a := range perCommit[c.ID] {
				a.c.Files = len(a.paths)
				a.c.Prompts = len(a.prompts)
				ids := make([]int64, 0, len(a.prompts))
				for id := range a.prompts {
					ids = append(ids, id)
				}
				sort.Slice(ids, func(i, j int) bool {
					ti, tj := a.prompts[ids[i]], a.prompts[ids[j]]
					if !ti.Equal(tj) {
						return ti.Before(tj)
					}
					return ids[i] < ids[j]
				})
				a.c.PromptActionIDs = ids
				if len(ids) > 0 {
					a.c.FirstPromptAt = a.prompts[ids[0]]
				}
				cs = append(cs, a.c)
			}
		}
		decided := false
		for _, g := range ownershipGates {
			if g.matches(c, len(cs)) {
				own.Reason = g.reason
				decided = true
				break
			}
		}
		if !decided {
			own.Reason = rankContributors(cs)
			own.OwnerSessionID = cs[0].SessionID
			own.ShareBasis, cs = assignShares(cs)
			own.Contributors = cs
		}
		out[c.ID] = own
	}
	return out
}

// assignShares stamps each contributor's Share on the code-lines basis
// when any code line was carried, else on the files basis.
func assignShares(cs []CommitContributor) (string, []CommitContributor) {
	totalLines, totalFiles := 0, 0
	for _, c := range cs {
		totalLines += c.CodeLines
		totalFiles += c.Files
	}
	basis := ShareBasisFiles
	if totalLines > 0 {
		basis = ShareBasisCodeLines
	}
	for i := range cs {
		switch {
		case basis == ShareBasisCodeLines:
			cs[i].Share = float64(cs[i].CodeLines) / float64(totalLines)
		case totalFiles > 0:
			cs[i].Share = float64(cs[i].Files) / float64(totalFiles)
		}
	}
	return basis, cs
}

// SessionCommit is one commit a session contributed to, from that
// session's side: the "Commits" section of a session detail.
type SessionCommit struct {
	CommitID int64
	SHA      string
	// Owner is true when this session is the commit's owner.
	Owner bool
	// OwnerSessionID is the commit's owner (possibly another session).
	OwnerSessionID string
	Reason         string
	ShareBasis     string
	Contribution   CommitContributor
}

// CommitsBySession inverts an ownership map: for each session, every
// commit it contributed to, in ascending commit-id order (the caller
// re-sorts by committed_at when it has the commit rows).
func CommitsBySession(own map[int64]CommitOwnership) map[string][]SessionCommit {
	ids := make([]int64, 0, len(own))
	for id := range own {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	out := make(map[string][]SessionCommit)
	for _, id := range ids {
		o := own[id]
		for _, c := range o.Contributors {
			out[c.SessionID] = append(out[c.SessionID], SessionCommit{
				CommitID: o.CommitID, SHA: o.SHA,
				Owner:          c.SessionID == o.OwnerSessionID,
				OwnerSessionID: o.OwnerSessionID, Reason: o.Reason, ShareBasis: o.ShareBasis,
				Contribution: c,
			})
		}
	}
	return out
}
