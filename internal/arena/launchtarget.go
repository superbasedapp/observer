package arena

import "context"

// LaunchTarget is what a process Arena is about to start tells the
// admission callback (Options.Admission) about where it runs, carried on
// the callback's context (LaunchTargetFrom). The callback signature stays a
// tool name and a proxy URL; this is the one place the start directory
// reaches it, so a launch check never falls back to the daemon's own
// working directory.
type LaunchTarget struct {
	// Dir is the directory the process starts in: a candidate's worktree,
	// the temporary keep worktree of a judge_merge keep (judgeMergeKeep,
	// never the project root itself since OSH-R-006), or the stable scratch
	// directory emptied for each judge drive (the judge, judgeInScratch).
	Dir string
	// SourceRoot is the repository the process's worktree was made from (a
	// candidate's or the keep's), or "" when the process runs in nothing
	// made from it (the judge's scratch directory).
	SourceRoot string
	// ProjectRoot is the run's project root, the repository the operator
	// chose (for the judge too, which runs in scratch): the admission
	// checks it against the node's own launch policy (OSH-R-004).
	ProjectRoot string
	// ChildEnv are environment entries the admission adds to the process it
	// admitted ("NAME=value"), layered after the inherited environment.
	ChildEnv []string
}

type launchTargetKey struct{}

// ContextWithLaunchTarget carries t on ctx for the admission callback (the
// runner does this before each start; a test of a callback can too).
func ContextWithLaunchTarget(ctx context.Context, t *LaunchTarget) context.Context {
	return context.WithValue(ctx, launchTargetKey{}, t)
}

// LaunchTargetFrom returns the launch target the admission callback's
// context carries, and whether it carries one. The callback may append to
// its ChildEnv.
func LaunchTargetFrom(ctx context.Context) (*LaunchTarget, bool) {
	t, ok := ctx.Value(launchTargetKey{}).(*LaunchTarget)
	return t, ok && t != nil
}
