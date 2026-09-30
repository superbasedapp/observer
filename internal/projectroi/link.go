package projectroi

import (
	"sort"
	"time"
)

// Status is a prompt's attribution outcome (R4.5).
type Status string

const (
	// StatusCommitted means every file the prompt reached (after
	// supersede filtering) landed in a qualifying commit.
	StatusCommitted Status = "committed"
	// StatusPartial means some, but not all, reached files landed in a
	// qualifying commit.
	StatusPartial Status = "partial"
	// StatusUncommitted means the prompt reached at least one file but
	// none of them landed in a qualifying commit.
	StatusUncommitted Status = "uncommitted"
	// StatusSuperseded means the prompt had edits, but every one of
	// them was superseded by a strictly later prompt's edit to the
	// same file before that file's earliest carrying commit (R4.3).
	StatusSuperseded Status = "superseded"
	// StatusNoEdits means the prompt has no AI edits assigned to it at
	// all. It is still counted (e.g. for spend), never linked.
	StatusNoEdits Status = "no_edits"
)

// ChainFile is one (prompt, path) pair's outcome: how much of the file
// this prompt touched, whether a later prompt superseded it, and which
// commit (if any) carried it.
type ChainFile struct {
	PathHash string
	// Added / Modified / Deleted are CODE lines (Edit.CodeLines' rule: a
	// docs or config file contributes zero here while still counting as a
	// reached file).
	Added    int
	Modified int
	Deleted  int
	// Comment is the pair's added comment lines (Edit.CommentLines).
	Comment    int
	Superseded bool
	// CommitID is the id of the earliest qualifying commit that carried
	// this (prompt, path) pair, or 0 when none did (including when
	// Superseded is true).
	CommitID int64
}

// ChainCommit is one commit a prompt chain reached, with this prompt's
// share of that commit's total linked file set.
type ChainCommit struct {
	ID          int64
	SHA         string
	CommittedAt time.Time
	// Share is this prompt's file-count share of the commit's LINKED
	// SET — the union of files every prompt that reached this commit
	// contributed, not just this prompt's own files. It sums to 1
	// across every prompt that reached a given commit. This is a
	// different normalization than AttributeSpend's weighting, which
	// is self-normalized over one prompt's own reached commits — see
	// AttributeSpend's doc comment.
	Share float64
}

// PromptChain is one prompt's full attribution outcome: its edits,
// grouped per-file outcomes, the commits it reached, and its Status.
type PromptChain struct {
	Prompt  Prompt
	Edits   []Edit
	Files   []ChainFile
	Commits []ChainCommit
	Status  Status
}

// Linkage is the result of Link: one PromptChain per input Prompt (in
// input order), a commit->prompt-action-id index for the "linked
// prompts" side of a commit ledger row, and the edits that could not be
// assigned to any prompt.
type Linkage struct {
	Chains []PromptChain
	// ByCommit maps a commit id to the action ids of every prompt whose
	// reach set included a file that commit carried.
	ByCommit map[int64][]int64
	// Orphans are AI edits with no user_prompt before them in the same
	// session (R4.2). They are counted in spend (AttributeSpend's
	// Orphan bucket) but never linked to a prompt or a commit.
	Orphans []Edit
}

// commitRef is the slice of a Commit that matters once we've keyed by
// PathHash: which commit, and when.
type commitRef struct {
	id          int64
	sha         string
	committedAt time.Time
}

// fileKey identifies one (prompt, path) pair by the prompt's index into
// the caller's prompts slice.
type fileKey struct {
	promptIdx int
	pathHash  string
}

// aggEdit is the running aggregate for one (prompt, path) pair.
type aggEdit struct {
	added, modified, deleted, comment int
	// firstAt is the earliest At among the edits folded into this
	// pair — used by the R4.3 supersede check ("edited ... before the
	// earliest commit").
	firstAt time.Time
}

// earliestQualifyingCommit returns the earliest ref in refs (sorted
// ascending by committedAt, already restricted to reachable, non-merge
// commits carrying one path) that R4.4 says carries an edit made at at:
// committed strictly after at, within window of it. It is the single
// definition of "the commit that carries this (prompt, path) pair" —
// used both by the R4.3 supersede check (each prompt's OWN qualifying
// commit, never the path's globally-earliest one) and by R4.4's commit
// matching itself, so the two can never drift apart.
func earliestQualifyingCommit(refs []commitRef, at time.Time, window time.Duration) (commitRef, bool) {
	pos := sort.Search(len(refs), func(j int) bool { return refs[j].committedAt.After(at) })
	if pos < len(refs) && refs[pos].committedAt.Sub(at) <= window {
		return refs[pos], true
	}
	return commitRef{}, false
}

// Link implements the ordered attribution rule, R4.1-R4.7, over one
// project's prompts, AI edits and commits. It is a pure function: the
// same inputs always produce the same Linkage, and it does no I/O.
//
// Link is map-keyed on SessionID and PathHash throughout (R11) — never
// an O(prompts x commits) nested loop — so it scales to the sizes a
// real project's window can hold; see BenchmarkLink.
//
// The rule is walked top-down, one named stage per ordered step:
//
//  1. assignEditsToPrompts   — R4.1/R4.2: eligibility + sidechain fold
//     + last-prompt-in-session assignment.
//  2. indexCommitsByPath     — R4.4 indexing: reachable, non-merge
//     commits only, keyed by path, ascending by time.
//  3. supersedeByLaterPrompt — R4.3: per-file supersede against each
//     prompt's own qualifying commit.
//  4. matchCommits           — R4.4/R4.5: commit matching over what
//     supersede left standing, plus per-prompt Status.
//  5. attachChainCommits     — builds each chain's ordered Commits and
//     the commit->prompt ByCommit index once every prompt's counts are
//     known.
func Link(prompts []Prompt, edits []Edit, commits []Commit, opts Options) Linkage {
	window := opts.window()

	promptEdits, pathOrder, agg, orphans := assignEditsToPrompts(prompts, edits)

	commitByID, byPath := indexCommitsByPath(commits)

	superseded := supersedeByLaterPrompt(prompts, agg, byPath, window)

	chains, commitFileCounts, perPromptCommitCounts := matchCommits(
		prompts, promptEdits, pathOrder, agg, byPath, superseded, window)

	byCommit := attachChainCommits(prompts, chains, commitByID, commitFileCounts, perPromptCommitCounts)

	return Linkage{Chains: chains, ByCommit: byCommit, Orphans: orphans}
}

// assignEditsToPrompts implements R4.1/R4.2: every edit belongs to the
// LAST prompt at or before its own timestamp in the SAME session — the
// same rule for an ordinary edit and a sidechain one (R4.1/F20), since
// the loader stamps a sidechain edit's SessionID with the parent
// session before Link ever sees it, so no separate sidechain branch is
// needed here. An edit with no such prompt is an orphan (R4.2),
// returned separately and never assigned. It also folds every edit
// into its (prompt, path) aggregate (aggEdit), tracking the earliest
// edit time per pair for the R4.3 supersede check downstream, and
// records each prompt's paths in first-seen order.
func assignEditsToPrompts(prompts []Prompt, edits []Edit) (promptEdits [][]Edit, pathOrder [][]string, agg map[fileKey]*aggEdit, orphans []Edit) {
	promptsBySession := make(map[string][]int, len(prompts))
	for i, p := range prompts {
		promptsBySession[p.SessionID] = append(promptsBySession[p.SessionID], i)
	}
	for sid, idxs := range promptsBySession {
		sort.Slice(idxs, func(a, b int) bool { return prompts[idxs[a]].At.Before(prompts[idxs[b]].At) })
		promptsBySession[sid] = idxs
	}

	promptEdits = make([][]Edit, len(prompts))
	pathOrder = make([][]string, len(prompts)) // first-seen path order per prompt
	agg = make(map[fileKey]*aggEdit)

	for _, e := range edits {
		idxs := promptsBySession[e.SessionID]
		// pos = first index whose prompt.At is strictly after e.At; the
		// owning prompt, if any, is idxs[pos-1] (the LAST prompt at or
		// before e.At).
		pos := sort.Search(len(idxs), func(i int) bool { return prompts[idxs[i]].At.After(e.At) })
		if pos == 0 {
			orphans = append(orphans, e)
			continue
		}
		pIdx := idxs[pos-1]
		promptEdits[pIdx] = append(promptEdits[pIdx], e)

		k := fileKey{pIdx, e.PathHash}
		a, ok := agg[k]
		if !ok {
			a = &aggEdit{firstAt: e.At}
			agg[k] = a
			pathOrder[pIdx] = append(pathOrder[pIdx], e.PathHash)
		} else if e.At.Before(a.firstAt) {
			a.firstAt = e.At
		}
		if e.countsAsCode() {
			a.added += e.AddedCode
			a.modified += e.ModifiedCode
			a.deleted += e.DeletedCode
			a.comment += e.AddedComment
		}
	}

	return promptEdits, pathOrder, agg, orphans
}

// indexCommitsByPath implements the R4.4 indexing step: only
// reachable, non-merge commits by the LOCAL author ever "carry" anything,
// so a merge, an unreachable commit or a foreign-author commit (a
// teammate's commit pulled into the checkout, Commit.ForeignAuthor) is
// dropped here before any matching happens. The
// result is keyed by PathHash, ascending by CommittedAt, ready for
// earliestQualifyingCommit's binary search.
func indexCommitsByPath(commits []Commit) (commitByID map[int64]Commit, byPath map[string][]commitRef) {
	commitByID = make(map[int64]Commit, len(commits))
	byPath = make(map[string][]commitRef)
	for _, c := range commits {
		commitByID[c.ID] = c
		if c.IsMerge || !c.Reachable || c.ForeignAuthor {
			continue
		}
		for _, f := range c.Files {
			byPath[f.PathHash] = append(byPath[f.PathHash], commitRef{id: c.ID, sha: c.SHA, committedAt: c.CommittedAt})
		}
	}
	for path, refs := range byPath {
		sort.Slice(refs, func(i, j int) bool { return refs[i].committedAt.Before(refs[j].committedAt) })
		byPath[path] = refs
	}
	return commitByID, byPath
}

// supersedeByLaterPrompt implements R4.3: per-file supersede. It groups
// (prompt, path) pairs by path, ordered by the owning prompt's At. For
// EACH prompt in the pair, its "earliest commit that carries it" is ITS
// OWN earliest qualifying carrying commit (R4.4: reachable, non-merge,
// committed after this prompt's own At, within the link window) —
// never the path's globally-earliest carrying commit, which may
// predate the prompt entirely (a prior, unrelated commit that happened
// to also touch the path). A pair is superseded only when some
// STRICTLY later prompt (by prompt.At — equal-time prompts never
// supersede one another) also touched the path, with an edit timestamp
// strictly before that earlier prompt's own qualifying commit.
func supersedeByLaterPrompt(prompts []Prompt, agg map[fileKey]*aggEdit, byPath map[string][]commitRef, window time.Duration) map[fileKey]bool {
	promptsByPath := make(map[string][]int) // promptIdx list per path, order TBD
	for k := range agg {
		promptsByPath[k.pathHash] = append(promptsByPath[k.pathHash], k.promptIdx)
	}

	superseded := make(map[fileKey]bool, len(agg))
	for path, idxs := range promptsByPath {
		refs := byPath[path]
		if len(refs) == 0 {
			continue // nothing carries this path at all — nothing to supersede against
		}

		sort.Slice(idxs, func(a, b int) bool { return prompts[idxs[a]].At.Before(prompts[idxs[b]].At) })
		n := len(idxs)

		// suffixMinFirstAt[i] = the earliest edit firstAt among idxs[i:] —
		// lets each earlier prompt ask "did any strictly-later prompt on
		// this path edit before my own qualifying commit?" in one pass.
		suffixMinFirstAt := make([]time.Time, n)
		for i := n - 1; i >= 0; i-- {
			fa := agg[fileKey{idxs[i], path}].firstAt
			if i == n-1 || fa.Before(suffixMinFirstAt[i+1]) {
				suffixMinFirstAt[i] = fa
			} else {
				suffixMinFirstAt[i] = suffixMinFirstAt[i+1]
			}
		}

		for i := 0; i < n; i++ {
			pIdx := idxs[i]
			ownRef, ok := earliestQualifyingCommit(refs, prompts[pIdx].At, window)
			if !ok {
				continue // this prompt never reaches a qualifying commit itself — nothing to be superseded before
			}
			// j = first index with a STRICTLY later prompt.At than idxs[i]
			// (skips over any ties at the same timestamp, per R4.3).
			j := sort.Search(n, func(k int) bool { return prompts[idxs[k]].At.After(prompts[pIdx].At) })
			if j >= n {
				continue // no strictly later prompt touched this path
			}
			if suffixMinFirstAt[j].Before(ownRef.committedAt) {
				superseded[fileKey{pIdx, path}] = true
			}
		}
	}

	return superseded
}

// statusFor implements R4.5's status table over one prompt's reach
// (files left standing after supersede) and committed (of those, how
// many landed in a qualifying commit) counts. It assumes the prompt has
// at least one edit; StatusNoEdits is decided by the caller before
// reach/committed are even computed.
func statusFor(reach, committed int) Status {
	switch {
	case reach == 0:
		return StatusSuperseded
	case committed == 0:
		return StatusUncommitted
	case committed == reach:
		return StatusCommitted
	default:
		return StatusPartial
	}
}

// matchCommits implements R4.4/R4.5: commit matching over what
// supersede left standing, and the resulting per-prompt Status. A
// prompt with no edits at all is StatusNoEdits (R4.5) and never
// enters matching. For every other prompt, each of its surviving
// (non-superseded) files is matched against its OWN earliest
// qualifying commit (the same earliestQualifyingCommit rule
// supersedeByLaterPrompt uses, so the two can never drift apart), and
// statusFor turns the reach/committed counts into one Status. It also
// returns the running per-commit and per-prompt file counts that
// attachChainCommits needs to compute ChainCommit.Share.
func matchCommits(
	prompts []Prompt,
	promptEdits [][]Edit,
	pathOrder [][]string,
	agg map[fileKey]*aggEdit,
	byPath map[string][]commitRef,
	superseded map[fileKey]bool,
	window time.Duration,
) (chains []PromptChain, commitFileCounts map[int64]int, perPromptCommitCounts []map[int64]int) {
	chains = make([]PromptChain, len(prompts))
	// commitFileCounts[commitID] = total distinct (prompt,path) pairs
	// across ALL prompts that reached that commit — the denominator for
	// ChainCommit.Share.
	commitFileCounts = make(map[int64]int)
	// perPromptCommitCounts[promptIdx][commitID] = this prompt's own
	// count, the numerator for ChainCommit.Share.
	perPromptCommitCounts = make([]map[int64]int, len(prompts))

	for i, p := range prompts {
		paths := pathOrder[i]
		if len(paths) == 0 {
			chains[i] = PromptChain{Prompt: p, Status: StatusNoEdits}
			continue
		}
		files := make([]ChainFile, 0, len(paths))
		counts := make(map[int64]int)
		reach, committed := 0, 0
		for _, path := range paths {
			k := fileKey{i, path}
			a := agg[k]
			cf := ChainFile{PathHash: path, Added: a.added, Modified: a.modified, Deleted: a.deleted, Comment: a.comment}
			if superseded[k] {
				cf.Superseded = true
			} else {
				reach++
				if ref, ok := earliestQualifyingCommit(byPath[path], p.At, window); ok {
					cf.CommitID = ref.id
					committed++
					counts[cf.CommitID]++
					commitFileCounts[cf.CommitID]++
				}
			}
			files = append(files, cf)
		}
		perPromptCommitCounts[i] = counts

		chains[i] = PromptChain{Prompt: p, Edits: promptEdits[i], Files: files, Status: statusFor(reach, committed)}
	}

	return chains, commitFileCounts, perPromptCommitCounts
}

// attachChainCommits is the final pass: now that commitFileCounts is
// complete across every prompt, it builds each chain's ordered
// Commits (ascending by CommittedAt) with their ChainCommit.Share, and
// the commit->prompt-action-id Linkage.ByCommit index used by the
// "linked prompts" side of a commit ledger row. It mutates chains in
// place and returns byCommit.
func attachChainCommits(
	prompts []Prompt,
	chains []PromptChain,
	commitByID map[int64]Commit,
	commitFileCounts map[int64]int,
	perPromptCommitCounts []map[int64]int,
) map[int64][]int64 {
	byCommit := make(map[int64][]int64)
	for i, p := range prompts {
		counts := perPromptCommitCounts[i]
		if len(counts) == 0 {
			continue
		}
		ids := make([]int64, 0, len(counts))
		for id := range counts {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(a, b int) bool { return commitByID[ids[a]].CommittedAt.Before(commitByID[ids[b]].CommittedAt) })

		cc := make([]ChainCommit, 0, len(ids))
		for _, id := range ids {
			c := commitByID[id]
			total := commitFileCounts[id]
			share := 0.0
			if total > 0 {
				share = float64(counts[id]) / float64(total)
			}
			cc = append(cc, ChainCommit{ID: c.ID, SHA: c.SHA, CommittedAt: c.CommittedAt, Share: share})
			byCommit[id] = append(byCommit[id], p.ActionID)
		}
		chains[i].Commits = cc
	}

	return byCommit
}
