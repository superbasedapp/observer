package commitlog

import "strings"

// LsTreeArgs builds the argv to pass to git (after "git" itself, e.g.
// via gitview.RunReadOnly) for a recursive tree listing at sha.
//
//   - "-r" recurses into subtrees so every blob (and gitlink) in the
//     tree is a single record — the caller never has to walk "tree"
//     entries itself.
//   - "-z" NUL-terminates records instead of newlines, matching
//     ParseLsTree.
//   - paths in the output are relative to the invocation's CURRENT
//     directory, i.e. the "-C <root>" the caller runs git with — there
//     is no --full-name/--full-tree here, so a project rooted in a
//     subdirectory of the repository sees paths already relative to
//     ITS root, with no rebase step needed on the caller's side.
//   - pathspec, when non-empty, is appended after the "--" separator to
//     scope the listing to a subtree or file, the same convention as
//     PageArgs' subtree argument; pathspec == "" lists the whole tree.
func LsTreeArgs(sha, pathspec string) []string {
	args := []string{"ls-tree", "-r", "-z", sha, "--"}
	if pathspec != "" {
		args = append(args, pathspec)
	}
	return args
}

// TreeEntry is one blob or gitlink (submodule commit) entry from a `git
// ls-tree -r` listing, as decoded by ParseLsTree. Plain "tree" entries
// never appear here — see ParseLsTree.
type TreeEntry struct {
	// Mode is the raw six-digit octal mode string (e.g. "100644",
	// "100755", "120000", "160000" for a gitlink).
	Mode string
	// Type is git's object type: "blob" or "commit" (a gitlink).
	Type string
	// OID is the object's full hex object id.
	OID string
	// RelPath is relative to the invocation's working directory (see
	// LsTreeArgs) and already forward-slash-separated, as git emits it.
	RelPath string
}

// ParseLsTree decodes the output of a `git ls-tree -r -z` invocation
// built with LsTreeArgs into a slice of TreeEntry.
//
// Each NUL-terminated record is shaped
// "<mode> <type> <oid>\t<path>". A record that doesn't split into
// exactly those four pieces is skipped rather than failing the whole
// listing. Only "blob" and "commit" (gitlink) entries are kept — with
// "-r" git does not emit "tree" entries for anything it recurses into,
// but a defensive skip costs nothing if that ever changes upstream.
func ParseLsTree(data []byte) []TreeEntry {
	var entries []TreeEntry
	for _, rec := range strings.Split(string(data), "\x00") {
		if rec == "" {
			continue
		}
		tab := strings.IndexByte(rec, '\t')
		if tab < 0 {
			continue
		}
		header, path := rec[:tab], rec[tab+1:]
		fields := strings.SplitN(header, " ", 3)
		if len(fields) != 3 {
			continue
		}
		mode, typ, oid := fields[0], fields[1], fields[2]
		if typ != "blob" && typ != "commit" {
			continue
		}
		entries = append(entries, TreeEntry{
			Mode:    mode,
			Type:    typ,
			OID:     oid,
			RelPath: path,
		})
	}
	return entries
}
