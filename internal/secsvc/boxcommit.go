//go:build !sbo_omit_security

package secsvc

import "context"

// boxcommit.go: what the findings writer needs to know about a commit a
// sandbox box made (security plan 4.8 "Copy workspaces", M7; lane
// sec-box). Box work reaches the source repository on a box ref
// (refs/observer/sandbox/<run> from the return step, or the worktree
// source's refs/heads/observer-sandbox/<id>/<label> branch), not on HEAD.
// Its commit-scope run is recorded through RecordRun like every other
// run, with three differences RecordRun applies when the context carries
// a BoxCommit:
//
//   - every finding's lineage names the run (secfinding.Lineage.RunID);
//   - the run row's target names the commit, the ref and the run
//     (BoxCommitTarget), so the box-ref walk skips a commit the store
//     already holds a run for (store.SecBoxCommitsScanned);
//   - the run closes nothing: a box branch that removes a secret does not
//     remove it from the source's own tree, which the HEAD walk and the
//     post-write scan speak for.

type boxCommitKey struct{}

// BoxCommit names the box commit a run is recorded for. Commit is ""
// for the unknown run that records a walk's skipped remainder. RefsLeft
// and ListCap are set only on a tick's aggregate unknown runs (lane
// sec-box audit findings 2 and 3): the box refs the tick left for the next
// one, and the listing cap a repository's box refs went past.
type BoxCommit struct {
	RunID    string
	Ref      string
	Commit   string
	RefsLeft int
	ListCap  int
}

// WithBoxCommit returns ctx carrying b for RecordRun.
func WithBoxCommit(ctx context.Context, b BoxCommit) context.Context {
	return context.WithValue(ctx, boxCommitKey{}, b)
}

// BoxCommitFrom returns the BoxCommit ctx carries.
func BoxCommitFrom(ctx context.Context) (BoxCommit, bool) {
	b, ok := ctx.Value(boxCommitKey{}).(BoxCommit)
	return b, ok
}

// BoxCommitTarget is the target_json of a box commit's run row. Box is
// always true, so the store can tell such a row from any other target.
type BoxCommitTarget struct {
	Box      bool   `json:"box"`
	Commit   string `json:"commit,omitempty"`
	Ref      string `json:"ref,omitempty"`
	RunID    string `json:"run_id,omitempty"`
	RefsLeft int    `json:"refs_left,omitempty"`
	ListCap  int    `json:"list_cap,omitempty"`
}

// boxRunTarget is the run row's target for ctx: nil (no target, as
// before) when ctx carries no BoxCommit.
func boxRunTarget(ctx context.Context) any {
	b, ok := BoxCommitFrom(ctx)
	if !ok {
		return nil
	}
	return BoxCommitTarget{Box: true, Commit: b.Commit, Ref: b.Ref, RunID: b.RunID, RefsLeft: b.RefsLeft, ListCap: b.ListCap}
}
