package commitscan

import (
	"errors"
	"path/filepath"
	"strings"
)

// FailureKind names WHY a project's last commit scan did not succeed, so
// every surface (the Projects page banner, the list tooltip, `observer
// doctor`, the daemon log) can say what failed and what to do instead of
// a generic "the ledger may be stale" (2026-10-15 operator report). It is
// persisted beside the raw error text (project_commit_scan.last_error_kind,
// agent migration 164). The zero value means "no failure".
type FailureKind string

// The closed FailureKind vocabulary. Keep internal/store's
// commitCaptureStateFor, the web COMMIT_CAPTURE table and migration 164's
// backfill CASE in step with this list.
const (
	KindNone FailureKind = ""
	// KindGitMissing: the git binary is not on PATH (process-wide).
	KindGitMissing FailureKind = "git_missing"
	// KindNoFolder: the project has no real folder (an adapter filed its
	// sessions under a placeholder such as "[cursor]").
	KindNoFolder FailureKind = "no_folder"
	// KindRootMissing: the folder was deleted, moved, or is not mounted.
	KindRootMissing FailureKind = "root_missing"
	// KindNotRepo: the folder exists but is not inside a git repository.
	KindNotRepo FailureKind = "not_repo"
	// KindDubiousOwnership: git refuses the repository because a different
	// OS user owns it (safe.directory), common for /mnt/c from WSL.
	KindDubiousOwnership FailureKind = "dubious_ownership"
	// KindPermission: the folder or its .git is not readable.
	KindPermission FailureKind = "permission_denied"
	// KindTimeout: a git invocation ran past its time limit even at the
	// smallest page size.
	KindTimeout FailureKind = "timeout"
	// KindTooLarge: one commit's diff summary alone exceeds the byte cap.
	KindTooLarge FailureKind = "output_too_large"
	// KindRepoUnreadable: git reports a missing or corrupt object.
	KindRepoUnreadable FailureKind = "repo_unreadable"
	// KindOther: anything the table below does not recognise.
	KindOther FailureKind = "other"
)

// errPageTooLarge marks scanPage's "still overflows at the minimum page
// size" failure, and errPageTimeout its "still times out at the minimum
// page size" failure, so classification never depends on our own wording.
var (
	errPageTooLarge = errors.New("commitscan: git log page too large")
	errPageTimeout  = errors.New("commitscan: git log page timed out")
)

// GitFailure is the plain structural shape of one failed git invocation,
// as Options.Inspect extracts it (production: gitview.InspectError). It
// keeps this package free of a gitview type dependency.
type GitFailure struct {
	ExitCode int
	Stderr   string
	TimedOut bool
}

// failureFacts is everything one classification row may look at.
type failureFacts struct {
	err         error
	git         GitFailure
	isGit       bool
	unavailable bool
	notRepo     bool
}

// failureRule is one row of the ordered classification table.
type failureRule struct {
	kind  FailureKind
	match func(f failureFacts) bool
}

// missingObjectHints are git's C-locale diagnostics for an unreadable
// repository. Data, not a ladder.
var missingObjectHints = []string{
	"bad object", "not a valid object name", "invalid object name",
	"unable to read tree", "not a tree object", "loose object", "is corrupt",
	"corrupt", "index file smaller than expected", "bad index file",
	"bad revision", "unknown revision",
}

// isTimeout reports whether err is a git invocation our own time limit
// killed (through Options.Inspect).
func (s *Scanner) isTimeout(err error) bool {
	if s.opts.Inspect == nil {
		return false
	}
	g, ok := s.opts.Inspect(err)
	return ok && g.TimedOut
}

// failureRules is walked top-down; the first matching row wins. Order
// matters: a timeout is reported as a timeout even when git printed
// nothing, and "cannot change to" (chdir failed: the folder is gone) is
// checked before not-a-repo.
var failureRules = []failureRule{
	{KindGitMissing, func(f failureFacts) bool { return f.unavailable }},
	{KindTimeout, func(f failureFacts) bool {
		return errors.Is(f.err, errPageTimeout) || (f.isGit && f.git.TimedOut)
	}},
	{KindTooLarge, func(f failureFacts) bool { return errors.Is(f.err, errPageTooLarge) }},
	{KindRootMissing, func(f failureFacts) bool {
		return f.isGit && stderrHas(f.git.Stderr, "cannot change to")
	}},
	{KindNotRepo, func(f failureFacts) bool { return f.notRepo }},
	{KindDubiousOwnership, func(f failureFacts) bool {
		return f.isGit && stderrHas(f.git.Stderr, "dubious ownership")
	}},
	{KindPermission, func(f failureFacts) bool {
		return f.isGit && stderrHas(f.git.Stderr, "permission denied")
	}},
	{KindRepoUnreadable, func(f failureFacts) bool {
		if !f.isGit {
			return false
		}
		for _, h := range missingObjectHints {
			if stderrHas(f.git.Stderr, h) {
				return true
			}
		}
		return false
	}},
	{KindOther, func(failureFacts) bool { return true }},
}

func stderrHas(stderr, phrase string) bool {
	return strings.Contains(strings.ToLower(stderr), phrase)
}

// classify maps one scan failure onto the closed FailureKind vocabulary
// through failureRules. A nil err is KindNone.
func (s *Scanner) classify(err error) FailureKind {
	if err == nil {
		return KindNone
	}
	f := failureFacts{
		err:         err,
		unavailable: s.opts.Unavailable != nil && s.opts.Unavailable(err),
		notRepo:     s.isNotRepo(err),
	}
	if s.opts.Inspect != nil {
		f.git, f.isGit = s.opts.Inspect(err)
	}
	for _, r := range failureRules {
		if r.match(f) {
			return r.kind
		}
	}
	return KindOther
}

// rootKind classifies a root the Scannable check rejected: a value that is
// not an absolute path at all (an adapter's "[cursor]" placeholder) has no
// folder; anything else is a folder that is gone or unmounted.
func rootKind(root string) FailureKind {
	if looksAbsolute(root) {
		return KindRootMissing
	}
	return KindNoFolder
}

// looksAbsolute accepts a POSIX absolute path and a Windows drive or UNC
// path, whatever OS the daemon runs on.
func looksAbsolute(p string) bool {
	if filepath.IsAbs(p) || strings.HasPrefix(p, "/") || strings.HasPrefix(p, `\\`) {
		return true
	}
	return len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/') &&
		((p[0] >= 'a' && p[0] <= 'z') || (p[0] >= 'A' && p[0] <= 'Z'))
}

// isStructural reports whether a failure kind is STRUCTURAL (the folder is
// gone, has never existed, or is not a repository): only a change on disk
// can clear it, so its failure count is pinned at 1 and it is re-checked
// on a slow cadence instead of backing off. Every other kind (a timeout,
// an unrecognised error) may clear on its own and takes the backoff.
func isStructural(k FailureKind) bool {
	switch k {
	case KindNoFolder, KindRootMissing, KindNotRepo:
		return true
	}
	return false
}
