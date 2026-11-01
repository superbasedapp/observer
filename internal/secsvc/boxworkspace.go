//go:build !sbo_omit_security

package secsvc

import (
	"path/filepath"
	"strings"
)

// boxworkspace.go resolves where a write or a commit in a sandbox run
// really is (security plan 4.8 "Copy workspaces" and its three-row table,
// 5.3 the post-write seam, M7; lane sec-box). The facts come from the
// host-written relay run records (sandbox plan section 6, revision 5: the
// workspace delivery is a launch fact); a guest-reported fact never
// reaches this table, so nothing the box says can raise a tree to
// "visible". Pure: the caller reads the records and the backend rows.

// CopyRun is one sandbox run's workspace facts, from its host-written
// run record.
type CopyRun struct {
	RunID string
	// Copy: the run's delivery is a copy (anything but the live tree).
	Copy bool
	// WorkspaceDir is the run's workspace as the host recorded it: the
	// tree its sessions are attributed to.
	WorkspaceDir string
	// CopyHostPath is the copy's host path when the record says the host
	// can see it.
	CopyHostPath string
	// InBox: the run's tree lives only inside the box (a remote box, a
	// disk image), or the run's backend could not be told, so the host
	// copy is not the tree the agent edits.
	InBox bool
	// ProjectRoot is the source project the host attributed the run to
	// (the record's project root, never a path the box reported): a copy's
	// per-project floors are its source project's (lane LEFT-SEC).
	ProjectRoot string
}

// CopyKind is where a tree's writes are read.
type CopyKind string

// The CopyKind values (the rows of the 4.8 table).
const (
	// CopyLive: no copy run works on the tree (today's behaviour), or the
	// run edits the live tree.
	CopyLive CopyKind = "live"
	// CopyVisible: a copy the host can see; read under Root.
	CopyVisible CopyKind = "copy_visible"
	// CopyInBox: a copy only inside the box; nothing on the host speaks
	// for it (post-write: not_scanned copy_workspace; commit: unknown).
	CopyInBox CopyKind = "copy_in_box"
)

// CopyResolution is one tree's answer.
type CopyResolution struct {
	Kind CopyKind
	// Root is the tree to read for CopyVisible: the same place as the
	// asked tree, in the host copy ("" otherwise).
	Root  string
	RunID string
}

// copyRule is one row of the resolution table, walked top-down.
type copyRule struct {
	name  string
	match func(r CopyRun) bool
	kind  CopyKind
}

// copyRules decide a matched run's row.
var copyRules = []copyRule{
	{"live delivery", func(r CopyRun) bool { return !r.Copy }, CopyLive},
	{"tree only in the box", func(r CopyRun) bool { return r.InBox }, CopyInBox},
	{"no host path in the record", func(r CopyRun) bool { return strings.TrimSpace(r.CopyHostPath) == "" }, CopyInBox},
	{"copy the host can see", func(CopyRun) bool { return true }, CopyVisible},
}

// ResolveCopyWorkspace answers for tree (a project root as the store
// records it, or a commit's working directory): the run whose workspace
// or copy path holds it decides through copyRules; a tree no run holds is
// CopyLive. Runs are tried in order; the first that holds tree wins.
func ResolveCopyWorkspace(runs []CopyRun, tree string) CopyResolution {
	if strings.TrimSpace(tree) == "" {
		return CopyResolution{Kind: CopyLive}
	}
	for _, r := range runs {
		inWorkspace := pathHolds(r.WorkspaceDir, tree)
		if !inWorkspace && !pathHolds(r.CopyHostPath, tree) {
			continue
		}
		for _, rule := range copyRules {
			if !rule.match(r) {
				continue
			}
			out := CopyResolution{Kind: rule.kind, RunID: r.RunID}
			if rule.kind == CopyVisible {
				// The same place in the host copy: tree's offset under
				// the workspace, or tree itself when the copy path holds it.
				out.Root = filepath.Clean(tree)
				if inWorkspace {
					if rel, err := filepath.Rel(filepath.Clean(r.WorkspaceDir), filepath.Clean(tree)); err == nil {
						out.Root = filepath.Join(filepath.Clean(r.CopyHostPath), rel)
					}
				}
			}
			return out
		}
	}
	return CopyResolution{Kind: CopyLive}
}

// ResolveCopyWorkspaceIndex is ResolveCopyWorkspace over an index of the
// run records that may be incomplete (more records than the index reads;
// lane sec-box audit finding 6): a tree no indexed run holds may belong to
// an unindexed copy run, so it is CopyInBox (unknown, never live or host
// clean) while the index is incomplete. A tree an indexed run holds is
// answered by that run as before.
func ResolveCopyWorkspaceIndex(runs []CopyRun, incomplete bool, tree string) CopyResolution {
	r := ResolveCopyWorkspace(runs, tree)
	if incomplete && r.Kind == CopyLive && r.RunID == "" && strings.TrimSpace(tree) != "" {
		return CopyResolution{Kind: CopyInBox}
	}
	return r
}

// SourceTreeOf answers, for a tree a copy run works on (its workspace or
// its host copy, or a directory inside either), the same place in the
// run's source project: the project root the host recorded, joined with
// tree's offset under the copy. ok is false for a tree no copy run holds,
// a live run, or a run with no recorded source distinct from its copy, so
// the caller keeps tree (lane LEFT-SEC: a copy's findings and gates meet
// its source project's security.scanning sections). Runs are tried in
// order; the first that holds tree wins.
func SourceTreeOf(runs []CopyRun, tree string) (string, bool) {
	if strings.TrimSpace(tree) == "" {
		return "", false
	}
	tree = filepath.Clean(tree)
	for _, r := range runs {
		if !r.Copy || strings.TrimSpace(r.ProjectRoot) == "" {
			continue
		}
		for _, base := range []string{r.WorkspaceDir, r.CopyHostPath} {
			if !pathHolds(base, tree) {
				continue
			}
			src := filepath.Clean(r.ProjectRoot)
			if pathHolds(src, tree) {
				// The copy is the source itself (or inside it): nothing to map.
				return "", false
			}
			rel, err := filepath.Rel(filepath.Clean(base), tree)
			if err != nil {
				return "", false
			}
			return filepath.Join(src, rel), true
		}
	}
	return "", false
}

// pathHolds reports whether p is root or inside it (both cleaned).
func pathHolds(root, p string) bool {
	if strings.TrimSpace(root) == "" {
		return false
	}
	root, p = filepath.Clean(root), filepath.Clean(p)
	return p == root || strings.HasPrefix(p, root+string(filepath.Separator))
}

// TreeOnHost reports whether a run whose isolation stack is stack edits a
// tree the host can see: every layer is a known local backend (location
// answers a backend id's location, ok false for an unknown id). An empty
// stack or an unknown layer is not on the host (honest: never read a tree
// that may not be the box's).
func TreeOnHost(stack []string, local func(id string) (isLocal, ok bool)) bool {
	if len(stack) == 0 || local == nil {
		return false
	}
	for _, id := range stack {
		isLocal, ok := local(id)
		if !ok || !isLocal {
			return false
		}
	}
	return true
}
