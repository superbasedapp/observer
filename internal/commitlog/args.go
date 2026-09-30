package commitlog

import "strconv"

// logFormat is the --format argument's payload: a record separator
// (git's %x1e escape, ASCII RS — chosen because it cannot appear in any
// of the fields below) followed by five NUL-separated (%x00) fields —
// full SHA (%H), space-separated parent SHAs (%P), author name (%an),
// author date in strict ISO 8601 (%aI), committer date in strict ISO
// 8601 (%cI), and the one-line subject (%s). "tformat:" (not "format:")
// terminates every record with a newline, including the last, so
// ParseLog's record/line splitting needs no special-casing for the final
// commit in the stream.
//
// ONE format only. A second invocation with --name-status was considered
// (to get a real per-file status code) and rejected — correlating two
// separate git outputs by position is fragile (plan §3.1); CommitFile's
// Status is left best-effort zero instead (see types.go).
const logFormat = `%x1e%H%x00%P%x00%an%x00%aI%x00%cI%x00%s`

// Args builds the argv to pass to git (after "git" itself, e.g. via
// gitview.RunReadOnly) for a HEAD-only commit-history scan.
//
//   - "HEAD" only (never --all) — plan R2/F5: the page states it
//     reflects the checked-out branch; an all-refs scan has no single
//     linear watermark to resume from.
//   - "--no-renames" — plan R2/F4: a rename degrades to a delete+add
//     pair (the loc-tracking "no move detection" posture) rather than
//     the fragile "old => new" numstat shape a rename produces.
//   - "--date-order" makes the watermark (the last committer time seen)
//     a meaningful cutover point for the next scan.
//   - sinceRFC3339, when non-empty, becomes "--since=<value>" so a
//     re-scan only asks git for commits at or after the caller's
//     watermark (the caller applies its own overlap window before
//     calling Args, e.g. watermark-1h).
//   - max, when > 0, becomes "-n <max>" (the caller's per-tick commit
//     cap, e.g. 500). max <= 0 means unbounded (used by
//     `observer backfill --commits`'s full-history scan).
//   - "--numstat" plus "--format=tformat:<logFormat>" is the ONE output
//     shape this package's ParseLog understands.
//   - the trailing "--" stops git from treating sinceRFC3339 or any
//     other token as a pathspec.
//
// Merge commits are NOT excluded (no --no-merges): they count as
// commits but git emits no --numstat lines for them by default, so they
// naturally arrive with Files == nil; ParseLog also sets Commit.IsMerge
// from the parent count so a caller can treat them specially (plan R4.4:
// merges never carry attribution).
func Args(sinceRFC3339 string, max int) []string {
	return PageArgsRev("", sinceRFC3339, max, 0, "")
}

// PageArgs is Args with a page offset and an optional subtree pathspec:
// skip > 0 appends `--skip=<skip>` so a caller can walk a long history in
// bounded pages (`-n max`, newest first) instead of one unbounded `git
// log --numstat` that a per-invocation timeout would kill on a large
// repository; subtree != "" is a git PATHSPEC appended AFTER the `--`
// separator so a project rooted in a SUBDIRECTORY of a repository sees
// only the commits that touched its subtree, not the whole repository's
// history. A pathspec is CWD-relative, and the scanner runs with `-C
// <project root>`, so the caller passes "." (internal/commitscan.
// subtreePathspec), never the toplevel-relative prefix. skip <= 0 and
// subtree == "" is exactly Args.
func PageArgs(sinceRFC3339 string, max, skip int, subtree string) []string {
	return PageArgsRev("", sinceRFC3339, max, skip, subtree)
}

// PageArgsRev is PageArgs with an explicit revision to walk instead of
// the literal ref name "HEAD" — rev == "" is exactly PageArgs' prior
// fixed "HEAD" behaviour (Args and PageArgs are now thin wrappers over
// this, so every existing caller/test is unchanged). A caller paging a
// long history across MULTIPLE git invocations
// (internal/commitscan.Scanner.FullScan) resolves HEAD to a concrete sha
// ONCE before the first page and passes that same sha here for every
// page (plan review F16): re-resolving the literal ref "HEAD" on each
// invocation would let a rebase, reset, or fast-forward landing between
// two pages of the SAME scan skip or duplicate commits, since `--skip`
// is an OFFSET into whatever history the revision names at invocation
// time.
func PageArgsRev(rev, sinceRFC3339 string, max, skip int, subtree string) []string {
	if rev == "" {
		rev = "HEAD"
	}
	args := []string{"log", rev, "--no-renames", "--no-color", "--date-order"}
	if max > 0 {
		args = append(args, "-n", strconv.Itoa(max))
	}
	if skip > 0 {
		args = append(args, "--skip="+strconv.Itoa(skip))
	}
	if sinceRFC3339 != "" {
		args = append(args, "--since="+sinceRFC3339)
	}
	args = append(args, "--numstat", "--format=tformat:"+logFormat, "--")
	if subtree != "" {
		args = append(args, subtree)
	}
	return args
}
