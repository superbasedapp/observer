package guidance

import "strings"

// -----------------------------------------------------------------------------
// Root selection.
//
// The store knows every directory a session has ever run in, which on a
// working machine is not the same thing as "every project worth
// inventorying": throwaway agent scratchpads, harness arenas under
// ~/.observer and anything the OS handed out under its temp dir all
// appear there, and each one costs a full depth-capped walk per pass.
//
// The decision is a DATA TABLE walked top-down (CLAUDE.md rule #5), not
// a conditional ladder, and it is pure: the caller injects the two host
// directories rather than this package resolving them (rule #1).
// -----------------------------------------------------------------------------

// RootFilter decides which project roots are worth scanning. Its fields
// are host facts the caller resolves (os.TempDir, the observer home);
// an empty field simply disables the rule that reads it, so the zero
// RootFilter still applies the host-independent rules.
type RootFilter struct {
	// TempDir is the OS temp directory (os.TempDir()). Roots under it
	// are ephemeral by construction.
	TempDir string
	// ObserverDir is Observer's own state directory (~/.observer). Its
	// subtrees are harness arenas and sandboxes, not the operator's
	// projects.
	ObserverDir string
	// HomeDir is the operator's home directory. The directory itself is
	// never a project root (its subtrees may be).
	HomeDir string
	// SentinelRoots are roots that bypass every rule — the user-scope
	// sentinel ("~") above all, which is not a filesystem path and must
	// never be filtered out by a path predicate.
	SentinelRoots []string
}

// RootSkipReason is the short, stable label a skipped root is reported
// under. It is an enum-shaped string so a surface can group by it.
type RootSkipReason string

const (
	// RootSkipScratchpad — a path component is literally "scratchpad":
	// an agent's throwaway working directory, recreated per session.
	RootSkipScratchpad RootSkipReason = "scratchpad"
	// RootSkipTempDir — the root lives under the OS temp directory.
	RootSkipTempDir RootSkipReason = "temp_dir"
	// RootSkipMountRoot — the root IS a filesystem root, a bare mount
	// point (/mnt/<x>, /media/<x>, /Volumes/<x>) or the home directory
	// itself. A whole drive is never a project; a session that reported
	// one of these as its root was started from a non-project cwd, and
	// walking it four levels deep costs the entire per-root budget every
	// pass for nothing.
	RootSkipMountRoot RootSkipReason = "mount_root"
	// RootSkipObserverDir — the root lives under ~/.observer (harness
	// arenas, sandbox workspaces).
	RootSkipObserverDir RootSkipReason = "observer_dir"
)

// rootSkipRules is the ordered table. First match wins, and the reason
// it matched is what the pass reports — a skipped root is always
// skipped FOR a named reason, never silently dropped.
//
// Deliberately absent: any rule on "/mnt/…". A Windows project reached
// over DrvFs is slow, not illegitimate; it is bounded by the per-root
// time budget instead of being excluded from the inventory.
var rootSkipRules = []struct {
	Reason RootSkipReason
	Match  func(root string, f RootFilter) bool
}{
	{
		Reason: RootSkipScratchpad,
		Match: func(root string, _ RootFilter) bool {
			return hasPathComponent(root, "scratchpad")
		},
	},
	{
		Reason: RootSkipTempDir,
		Match: func(root string, f RootFilter) bool {
			return underDir(root, f.TempDir)
		},
	},
	{
		Reason: RootSkipMountRoot,
		Match: func(root string, f RootFilter) bool {
			return isMountRoot(root, f.HomeDir)
		},
	},
	{
		Reason: RootSkipObserverDir,
		Match: func(root string, f RootFilter) bool {
			return underDir(root, f.ObserverDir)
		},
	},
}

// Skip reports whether root should be left out of a scan pass, and why.
// A sentinel root is never skipped.
func (f RootFilter) Skip(root string) (RootSkipReason, bool) {
	root = normalizeRoot(root)
	if root == "" {
		return "", false
	}
	for _, s := range f.SentinelRoots {
		if normalizeRoot(s) == root {
			return "", false
		}
	}
	for _, rule := range rootSkipRules {
		if rule.Match(root, f) {
			return rule.Reason, true
		}
	}
	return "", false
}

// hasPathComponent reports whether any slash-separated component of
// root equals name. It is a COMPONENT test on purpose: a project
// legitimately called "scratchpad-notes" is not a scratchpad.
func hasPathComponent(root, name string) bool {
	for _, seg := range strings.Split(root, "/") {
		if seg == name {
			return true
		}
	}
	return false
}

// underDir reports whether root is dir itself or lives beneath it. An
// empty dir matches nothing, which is how a caller disables the rule.
func underDir(root, dir string) bool {
	dir = normalizeRoot(dir)
	if dir == "" || dir == "/" {
		return false
	}
	return root == dir || strings.HasPrefix(root, dir+"/")
}

// isMountRoot reports whether root is "/", the home directory itself, or
// a bare mount point (exactly two components under /mnt, /media or
// /Volumes). Anything deeper is a real directory and stays eligible.
func isMountRoot(root, home string) bool {
	if root == "/" {
		return true
	}
	if h := normalizeRoot(home); h != "" && h != "/" && root == h {
		return true
	}
	parts := strings.Split(strings.TrimPrefix(root, "/"), "/")
	if len(parts) == 1 {
		return parts[0] == "mnt" || parts[0] == "media" || parts[0] == "Volumes"
	}
	if len(parts) == 2 {
		switch parts[0] {
		case "mnt", "media", "Volumes":
			return true
		}
	}
	return false
}
