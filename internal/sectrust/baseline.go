package sectrust

import (
	"path"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
)

// The config baseline (security pillar plan section 5.1 item 1): the
// trust check's table files and their content digests are the project's
// snapshot, and the next snapshot's difference from it is what changed in
// the files an agent reads. This file is the pure half; the daemon loop
// (cmd/observer/launch_trust_baseline.go) stores snapshots through
// internal/store/sectrust.go and raises an agent_config finding per change.

// FileState is one table file of a snapshot.
type FileState struct {
	// Rel is slash-separated and relative to the repository root.
	Rel string
	// Class is the path-table class it was read as.
	Class string
	// SHA256 is the hex digest of its bytes; Size their count.
	SHA256 string
	Size   int64
	// Local reports one of the developer's own files (ownFile): a project
	// local scope file, .git/config or a dotenv file, which the agent's own
	// tools and git write during normal work.
	Local bool
}

// ChangeKind is how a file changed between two snapshots.
type ChangeKind string

// The closed ChangeKind vocabulary.
const (
	ChangeAdded   ChangeKind = "added"
	ChangeChanged ChangeKind = "changed"
	ChangeRemoved ChangeKind = "removed"
)

// FileChange is one difference between two snapshots.
type FileChange struct {
	Rel   string
	Class string
	Kind  ChangeKind
	// Old and New are the content digests before and after ("" for the
	// side that has none).
	Old, New string
	// Local is the file's FileState.Local (from the newer snapshot, else
	// the older one).
	Local bool
}

// Diff returns the changes from prev to cur, ordered by path. complete
// says cur read everything (the result was not truncated); a file absent
// from an incomplete snapshot may simply not have been read, so it is not
// reported as removed.
func Diff(prev, cur []FileState, complete bool) []FileChange {
	before := make(map[string]FileState, len(prev))
	for _, f := range prev {
		before[f.Rel] = f
	}
	var out []FileChange
	seen := make(map[string]bool, len(cur))
	for _, f := range cur {
		seen[f.Rel] = true
		old, ok := before[f.Rel]
		switch {
		case !ok:
			out = append(out, FileChange{Rel: f.Rel, Class: f.Class, Kind: ChangeAdded, New: f.SHA256, Local: f.Local})
		case old.SHA256 != f.SHA256:
			out = append(out, FileChange{Rel: f.Rel, Class: f.Class, Kind: ChangeChanged, Old: old.SHA256, New: f.SHA256, Local: f.Local})
		}
	}
	if complete {
		for _, f := range prev {
			if !seen[f.Rel] {
				out = append(out, FileChange{Rel: f.Rel, Class: f.Class, Kind: ChangeRemoved, Old: f.SHA256, Local: f.Local || ownFile(f.Rel)})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Rel < out[j].Rel })
	return out
}

// InTable reports whether rel (slash-separated, relative to the root a
// snapshot reads) is a file the snapshot over paths reads at that root: a
// plain row's path, a direct child of a directory row (one level deeper for
// a code directory, whose plugin packages are directories), or a match of
// a glob row segment by segment. Configuration-directory rows check links,
// not file contents, so they match nothing. It lets the baseline rescan a
// root as soon as an agent wrote one of its files, instead of on the next
// timer pass.
func InTable(rel string, paths []agentconfig.TrustPath) bool {
	rel = strings.TrimPrefix(path.Clean("/"+strings.ReplaceAll(rel, `\`, "/")), "/")
	if rel == "" || rel == "." {
		return false
	}
	for _, p := range paths {
		if p.Class == agentconfig.TrustConfigDir {
			continue
		}
		switch {
		case strings.HasSuffix(p.Rel, "/"):
			rest, ok := strings.CutPrefix(rel, p.Rel)
			if !ok || rest == "" {
				continue
			}
			depth := strings.Count(rest, "/")
			if depth == 0 || (depth == 1 && p.Class == agentconfig.TrustCode) {
				return true
			}
		case strings.ContainsAny(p.Rel, "*?["):
			if globMatch(p.Rel, rel) {
				return true
			}
		case p.Rel == rel:
			return true
		}
	}
	return false
}

// globMatch matches a table glob segment by segment, the way the check's
// glob expansion reads it.
func globMatch(pattern, rel string) bool {
	ps, rs := strings.Split(pattern, "/"), strings.Split(rel, "/")
	if len(ps) != len(rs) {
		return false
	}
	for i := range ps {
		if ok, err := path.Match(ps[i], rs[i]); err != nil || !ok {
			return false
		}
	}
	return true
}
