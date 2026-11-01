package workspace

// Request is the pure input to Plan: everything needed to decide the
// destination workspace path and the ordered git steps to prepare it,
// without touching the filesystem or a subprocess. The caller (U4
// termsvc / U5 cmd wiring) resolves ProjectRoot/ManagedRoot to absolute
// paths — and runs its own existing ValidateProjectRoot gate — before
// calling Plan; Plan re-validates the argv-safety properties (absolute,
// no "..", no leading '-', no control/whitespace) itself so it never
// trusts a caller to have done that.
type Request struct {
	// Source selects the preparation strategy (§4's table).
	Source Source

	// ProjectRoot is the validated source repository on disk. Required
	// for SourceLive, SourceCloneLocal, and SourceWorktree. Ignored for
	// SourceCloneRemote.
	ProjectRoot string

	// RemoteURL is the git remote to clone. Required for
	// SourceCloneRemote only, validated by ValidateRemoteURL.
	RemoteURL string

	// Branch, if non-empty, is checked out as a new branch in the
	// prepared workspace:
	//   - clone-local / clone-remote: `git -C <dest> checkout -b <Branch>`
	//     after the clone, only when non-empty.
	//   - worktree: the LABEL of the run's branch, which is always
	//     `observer-sandbox/<ID>/<Branch>` (WorktreeBranch; "work" when
	//     empty), so it never collides with a branch ProjectRoot has
	//     checked out.
	Branch string

	// StartPoint, for SourceWorktree only, is the full object id the
	// run's branch starts from (the caller reads ProjectRoot's HEAD
	// first), so the run's base is recorded exactly. Empty starts from
	// ProjectRoot's HEAD.
	StartPoint string

	// ManagedRoot is the daemon's workspaces directory
	// (<observerDir>/workspaces), an absolute path. Unused for
	// SourceLive.
	ManagedRoot string

	// ID is the caller-minted 16-byte base64url run id. It becomes the
	// managed-root subdirectory name (<ManagedRoot>/<ID>/<repoLeaf>) and
	// must be a single clean path segment.
	ID string

	// AllowRemoteClone gates SourceCloneRemote — the daemon runs
	// `git clone <url>` with the operator's ambient auth, so it is
	// opt-in ([terminal.sandbox].allow_remote_clone).
	AllowRemoteClone bool

	// AllowWorktreeSource gates SourceWorktree: it mounts the main
	// repository's .git folder writable in the box (its object store, the
	// worktree's own git dir and the run's branch; PlanWorktreeBox) and
	// attributes the sandboxed run to the main repository
	// ([terminal.sandbox].allow_worktree_source, off by default).
	AllowWorktreeSource bool

	// RemoteAllowedHosts, when non-empty, restricts SourceCloneRemote to
	// URLs whose host is in this list
	// ([terminal.sandbox].remote_allowed_hosts).
	RemoteAllowedHosts []string
}
