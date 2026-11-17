package gitroute

import "strings"

// Failure is one failed git read, in plain fields (the daemon builds it
// from gitview's error).
type Failure struct {
	// Unavailable: the program could not be started (interop off, the
	// file gone, exec format error).
	Unavailable bool
	// TimedOut: the read's own timeout killed it. Canceled: the caller's
	// context ended (the scan's budget).
	TimedOut bool
	Canceled bool
	// ExitCode is git's exit code (-1 when the process did not exit with
	// one), Stderr its diagnostic.
	ExitCode int
	Stderr   string
}

// failureRule is one row of the failure table: the first row whose when
// holds decides whether the WSL git runs instead.
type failureRule struct {
	why      string
	when     func(Failure) bool
	fallback bool
}

// failureRules is the failure table, read top to bottom. A row that falls
// back names a failure of the Windows route itself; any other failure is
// git's answer about the repository (an unborn HEAD, a missing object, a
// bad revision) and is kept, since the WSL git would give the same answer,
// only slower. Out of time is never retried: the scan's budget is spent.
var failureRules = []failureRule{
	{why: "the scan's time is up", when: func(f Failure) bool { return f.Canceled || f.TimedOut }},
	{why: "git.exe did not start", when: func(f Failure) bool { return f.Unavailable }, fallback: true},
	{why: "git.exe ended without an exit code", when: func(f Failure) bool { return f.ExitCode == -1 }, fallback: true},
	{why: "Windows git refused the repository's ownership (safe.directory)", when: stderrHas("dubious ownership"), fallback: true},
	{why: "Windows git could not enter the directory", when: stderrHas("cannot change to"), fallback: true},
	{why: "Windows git found no repository there", when: func(f Failure) bool {
		return f.ExitCode == 128 && stderrHas("not a git repository")(f)
	}, fallback: true},
}

func stderrHas(phrase string) func(Failure) bool {
	return func(f Failure) bool { return strings.Contains(strings.ToLower(f.Stderr), phrase) }
}

// Environmental reports whether a failed Windows-git read should be run
// again with the WSL git, and the row that decided.
func Environmental(f Failure) (bool, string) {
	for _, r := range failureRules {
		if r.when(f) {
			return r.fallback, r.why
		}
	}
	return false, "git's own answer"
}
