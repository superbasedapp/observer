package workspace

import "fmt"

// copyremove.go decides whether a sandboxed run's managed copy (a
// clone-local or clone-remote workspace under the managed root) may be
// removed on the person's click (lane RETURNS, audit item L1). Copy-then-
// delete: a copy goes only once what it holds is known to be somewhere else.
// The box's commits must have come back (a return that failed, is still to
// run, or left no record keeps the copy), and the copy's files must be
// exactly its last commit's, judged WITHOUT running git in the box-written
// copy (its config could make git run a program the box chose): the host
// lists the commit's tree from a repository it trusts and hashes the copy's
// files itself. Anything it cannot judge keeps the copy, and says why.

// The return states a copy can be in.
const (
	// CopyReturnPending: the run ended and its return has not run yet (or
	// the run is still going).
	CopyReturnPending = "pending"
	// CopyReturnReturned: the box's commits are on the run's returned ref.
	CopyReturnReturned = "returned"
	// CopyReturnNothingNew: the box made no commit the source lacks.
	CopyReturnNothingNew = "nothing_new"
	// CopyReturnRefused: the return was refused (the reason is kept).
	CopyReturnRefused = "refused"
	// CopyReturnUnknown: Observer has no record of the copy's return and no
	// returned ref names it.
	CopyReturnUnknown = "unknown"
)

// CopyRemovalFacts are what the host knows about one copy when the person
// asks to remove it, read again at that moment (never taken from the
// request).
type CopyRemovalFacts struct {
	// RunLive: the run still has its relay record.
	RunLive bool
	// Return is one of the CopyReturn* states.
	Return string
	// Stamped: the copy carries the host-git refusal stamp.
	Stamped bool
	// Compared: the copy's files were compared with its last commit;
	// CompareError says why not when they were not.
	Compared     bool
	CompareError string
	// Changed counts the last commit's files that are missing or differ in
	// the copy; Extra the copy's files that are not in it and that the
	// repository's ignore rules do not cover (or cannot be judged).
	Changed int
	Extra   int
}

// CopyRemovalVerdict is DecideCopyRemoval's answer.
type CopyRemovalVerdict struct {
	Remove bool
	// Reason says why the copy is kept, in plain words.
	Reason string
}

// copyRemovalRule is one row of the removal table, walked top-down; the
// first row that matches decides.
type copyRemovalRule struct {
	remove bool
	reason func(f CopyRemovalFacts) string
	match  func(f CopyRemovalFacts) bool
}

func fixedCopyReason(s string) func(CopyRemovalFacts) string {
	return func(CopyRemovalFacts) string { return s }
}

var copyRemovalRules = []copyRemovalRule{
	{reason: fixedCopyReason("the run is still going"), match: func(f CopyRemovalFacts) bool { return f.RunLive }},
	{reason: fixedCopyReason("Observer refused to run git on this copy, so its commits did not come back; look at it with a plain editor"), match: func(f CopyRemovalFacts) bool { return f.Stamped }},
	{reason: fixedCopyReason("its commits have not been brought back yet"), match: func(f CopyRemovalFacts) bool { return f.Return == CopyReturnPending }},
	{reason: fixedCopyReason("its commits did not come back, so the copy is the only place they are"), match: func(f CopyRemovalFacts) bool { return f.Return == CopyReturnRefused }},
	{reason: fixedCopyReason("Observer has no record that its commits came back"), match: func(f CopyRemovalFacts) bool {
		return f.Return != CopyReturnReturned && f.Return != CopyReturnNothingNew
	}},
	{reason: func(f CopyRemovalFacts) string {
		if f.CompareError == "" {
			return "Observer could not compare the copy with its last commit"
		}
		return "Observer could not compare the copy with its last commit: " + f.CompareError
	}, match: func(f CopyRemovalFacts) bool { return !f.Compared }},
	{reason: func(f CopyRemovalFacts) string {
		return fmt.Sprintf("%d file(s) in the copy are changed or missing since its last commit (work that never came back)", f.Changed)
	}, match: func(f CopyRemovalFacts) bool { return f.Changed > 0 }},
	{reason: func(f CopyRemovalFacts) string {
		return fmt.Sprintf("%d file(s) in the copy are not in its last commit and not ignored (work that never came back)", f.Extra)
	}, match: func(f CopyRemovalFacts) bool { return f.Extra > 0 }},
	{remove: true, match: func(CopyRemovalFacts) bool { return true }},
}

// DecideCopyRemoval says whether a copy may be removed now, and why not.
func DecideCopyRemoval(f CopyRemovalFacts) CopyRemovalVerdict {
	for _, r := range copyRemovalRules {
		if r.match(f) {
			v := CopyRemovalVerdict{Remove: r.remove}
			if r.reason != nil {
				v.Reason = r.reason(f)
			}
			return v
		}
	}
	return CopyRemovalVerdict{}
}

// LocalReturnRule is one row of the end-of-run return table: what a bwrap
// copy run's end does for its workspace source.
type LocalReturnRule struct {
	Source Source
	// Return: the run's commits are returned at its end.
	Return bool
	// Bare: into the run's host-created bare return repository (there is
	// no local source repository).
	Bare bool
	// Why says what happens instead when nothing is returned.
	Why string
}

// localReturnRules is the table, one row per source.
var localReturnRules = []LocalReturnRule{
	{Source: SourceLive, Why: "the agent worked in your own folder; there is nothing to bring back"},
	{Source: SourceCloneLocal, Return: true},
	{Source: SourceCloneRemote, Return: true, Bare: true},
	{Source: SourceWorktree, Why: "the run's branch is already in your repository (the worktree's own end keeps or removes it)"},
}

// LocalReturnFor is the end-of-run return rule of src.
func LocalReturnFor(src Source) (LocalReturnRule, bool) {
	for _, r := range localReturnRules {
		if r.Source == src {
			return r, true
		}
	}
	return LocalReturnRule{}, false
}
